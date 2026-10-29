/*
 * Copyright 2025 Scott Bender <scott@scottbender.net>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import camelCase from 'camelcase'
import WebSocket from 'ws'
import {
  ServerAPI,
  Plugin,
  Path,
  PathValue,
  SourceRef
} from '@signalk/server-api'
import {
  Component,
  getSupportedComponents,
  createComponent
} from './components'
import crypto from 'crypto'
import { Channel } from 'better-sse'

type PendingRequest = {
  request: any
  resolve: (value: any) => void
  reject: (reason?: any) => void
  timeout: NodeJS.Timeout
}

export type DeviceSettings = {
  enabled: boolean
  displayName: string | undefined
  devicePath: string | undefined
  [key: string]: any
}

export class Device {
  id: string | null = null
  connected: boolean = false
  address: string
  hostname: string | undefined
  name: string | undefined = undefined
  model: string | null = null
  gen: number | null = null
  components: { [key: string]: Component[] } = {}
  deviceSettings: DeviceSettings | undefined
  authFailed: boolean = true
  triedAuth: boolean = false

  private ws: WebSocket | null = null
  private next_id: number = 1
  private pendingRequests: { [key: number]: PendingRequest } = {}
  private sentMeta: boolean = false
  private app: ServerAPI
  private plugin: Plugin
  private reconnectAttempts: number = 0
  private maxReconnectAttempts: number = -1
  private reconnectTimeout: NodeJS.Timeout | null = null
  private shouldReconnect: boolean = true
  private isReconnecting: boolean = false
  private polling: boolean = false
  private pollFailures: number = 0
  sentStaticDeltas: boolean = false
  private authMessage: any = undefined
  private channel: Channel | null = null

  constructor(
    app: ServerAPI,
    plugin: Plugin,
    channel: Channel | null,
    address: string,
    hostname: string,
    id?: string,
    deviceSettings?: DeviceSettings,
    model?: string
  ) {
    this.address = address
    this.app = app
    this.plugin = plugin
    this.channel = channel
    this.hostname = hostname
    this.maxReconnectAttempts = -1
    this.shouldReconnect = true
    this.id = id || null
    this.model = model || null
    if (deviceSettings) {
      this.setDeviceSettings(deviceSettings)
    }
  }

  setDeviceSettings(deviceSettings: DeviceSettings) {
    // Configure reconnection parameters from device settings or use defaults
    this.deviceSettings = deviceSettings
    this.maxReconnectAttempts = deviceSettings?.maxReconnectAttempts ?? -1
    this.shouldReconnect = deviceSettings?.enableReconnection !== false // Default to true unless explicitly disabled
    this.registerForPuts()
  }

  private debug(msg: string, ...args: any[]) {
    this.app.debug(msg, ...args)
  }

  private createWebSocketConnection(): Promise<WebSocket> {
    return new Promise((resolve, reject) => {
      try {
        const ws = new WebSocket(`ws://${this.hostname || this.address}/rpc`)

        const onOpen = () => {
          this.debug(`Connected to device at ${this.address}`)
          ws.removeListener('error', onError)
          resolve(ws)
        }

        const onError = (error: any) => {
          ws.removeListener('open', onOpen)
          reject(error)
          this.attemptReconnection()
        }

        ws.once('open', onOpen)
        ws.once('error', onError)
      } catch (error) {
        reject(error)
        this.attemptReconnection()
      }
    })
  }

  async connect() {
    this.shouldReconnect = true
    this.reconnectAttempts = 0
    this.isReconnecting = false
    this.sentStaticDeltas = false
    this.sentMeta = false

    this.debug(`Connecting to device at ${this.address}`)
    // Mark the connect as in progress so poll() doesn't start a parallel one.
    this.isReconnecting = true
    try {
      this.ws = await this.createWebSocketConnection()
      const result = await this.setupConnection()
      this.isReconnecting = false
      return result
    } catch (error) {
      this.isReconnecting = false
      // Retry unless setupConnection gave up for good (auth failures call
      // disconnect(), which clears shouldReconnect; attemptReconnection checks it).
      this.attemptReconnection()
      throw error
    }
  }

  private async setupConnection() {
    try {
      this.setupWebSocketHandlers()

      const deviceInfo = await this.send('Shelly.GetDeviceInfo')
      this.id = deviceInfo.id
      this.name = deviceInfo.name || null
      this.model = deviceInfo.model
      this.gen = deviceInfo.gen

      this.debug(
        `Initial device information retrieved successfully from ${this.address}: ${this.id} (${this.model}, Gen ${this.gen})`
      )
      this.debug(JSON.stringify(deviceInfo, null, 2))

      await this.setupDevice()
      this.authFailed = false
      this.connected = true
    } catch (error: any) {
      if (error instanceof SendError) {
        if (error.code === 401 && this.deviceSettings?.password) {
          this.debug(
            `Authentication required for device ${this.id} at ${this.address}, retrying with credentials`
          )
          this.setupAuthMessage(JSON.parse(error.message))
          this.triedAuth = true
          try {
            await this.setupDevice()
            this.authFailed = false
            this.connected = true
            this.debug(
              `Successfully authenticated with device ${this.id} at ${this.address}`
            )
            return
          } catch (err) {
            this.authFailed = true
            this.app.error(
              `Failed to authenticate with device ${this.id} ${this.address}`
            )
            this.disconnect()
            throw err
          }
          return
        } else if (error.code === 401) {
          this.authFailed = true
          this.triedAuth = true
          this.app.error(
            `Failed to authenticate with device ${this.id} ${this.address}: no password set`
          )
          this.disconnect()
          throw error
        }
      }
      this.app.error(`Failed to connect to device ${this.address}: ${error}`)
      this.dropSocket()
      throw error
    }
  }

  private setupAuthMessage(errorMessage: any) {
    const hash = (parts: any[]) => {
      return crypto.createHash('sha256').update(parts.join(':')).digest('hex')
    }

    const username = 'admin'
    const password = this.deviceSettings!.password
    const cnonce = Math.round(Math.random() * 1000000)
    const ha1 = hash([username, errorMessage.realm, password])
    const ha2 = hash(['dummy_method', 'dummy_uri'])
    const response = [
      ha1,
      errorMessage.nonce,
      errorMessage.nc,
      cnonce,
      'auth',
      ha2
    ]

    this.authMessage = {
      realm: errorMessage.realm,
      username,
      nonce: errorMessage.nonce,
      cnonce,
      response: hash(response),
      algorithm: 'SHA-256'
    }
  }

  private async setupDevice() {
    const result = await this.send('Shelly.GetStatus')
    this.debug(`Initial device status retrieved successfully from ${this.id}`)
    this.debug(JSON.stringify(result, null, 2))
    this.getCapabilities(result)
    this.registerForPuts()
    this.sendDeltas(result)
  }

  private setupWebSocketHandlers() {
    if (!this.ws) return

    this.ws.on('message', (message) => {
      const parsedMessage = JSON.parse(message.toString())
      //this.debug(`Received message from device ${this.id}: ${JSON.stringify(parsedMessage)}`)

      if (parsedMessage.method === 'NotifyStatus') {
        this.sendDeltas(parsedMessage.params)
      } else {
        const pendingRequest = this.pendingRequests[parsedMessage.id]
        if (pendingRequest) {
          clearTimeout(pendingRequest.timeout)
          if (parsedMessage.error) {
            pendingRequest.reject(
              new SendError(
                parsedMessage.error.message,
                parsedMessage.error.code
              )
            )
          } else {
            pendingRequest.resolve(parsedMessage.result)
          }
          delete this.pendingRequests[parsedMessage.id]
        }
      }
    })

    this.ws.on('error', (error) => {
      this.app.error(
        `WebSocket error for device ${this.id || this.address}: ${error}`
      )
      if (this.connected) {
        this.connected = false
        this.authMessage = undefined
        this.attemptReconnection()
      }
    })

    this.ws.on('close', (code, reason) => {
      this.debug(
        `WebSocket connection closed for device ${
          this.id || this.address
        }. Code: ${code}, Reason: ${reason}`
      )
      if (this.connected) {
        this.connected = false
        this.authMessage = undefined
        this.attemptReconnection()
      }
    })
  }

  private attemptReconnection() {
    if (!this.shouldReconnect || this.isReconnecting) {
      return
    }

    if (
      this.maxReconnectAttempts != -1 &&
      this.reconnectAttempts >= this.maxReconnectAttempts
    ) {
      this.app.error(
        `Max reconnection attempts (${
          this.maxReconnectAttempts
        }) reached for device ${this.id || this.address}. Giving up.`
      )
      return
    }

    this.isReconnecting = true
    this.reconnectAttempts++

    // Calculate exponential backoff delay (1s, 2s, 4s, 8s, 16s, max 10s)
    const delay = Math.min(
      1000 * Math.pow(2, this.reconnectAttempts - 1),
      10000
    )

    this.debug(
      `Attempting to reconnect to device ${
        this.id || this.address
      } in ${delay}ms (attempt ${this.reconnectAttempts}/${
        this.maxReconnectAttempts
      })`
    )

    this.reconnectTimeout = setTimeout(async () => {
      try {
        this.debug(`Reconnecting to device ${this.id || this.address}...`)
        this.dropSocket()
        this.ws = await this.createWebSocketConnection()
        await this.setupConnection()
        this.isReconnecting = false
        this.reconnectAttempts = 0
        this.debug(
          `Successfully reconnected to device ${this.id || this.address}`
        )
      } catch (error: any) {
        this.debug(
          `Reconnection attempt ${
            this.reconnectAttempts
          } failed for device ${this.id || this.address}: ${error}`
        )
        this.authMessage = undefined
        this.isReconnecting = false

        // Schedule next reconnection attempt
        this.attemptReconnection()
      }
    }, delay)
  }

  disconnect() {
    // Stop any reconnection attempts
    this.shouldReconnect = false
    this.isReconnecting = false

    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout)
      this.reconnectTimeout = null
    }

    if (this.ws) {
      this.connected = false
      this.ws.close()
      this.ws = null
    }

    // Clear any pending requests
    Object.values(this.pendingRequests).forEach((request) => {
      clearTimeout(request.timeout)
      request.reject(new Error('Device disconnected'))
    })
    this.pendingRequests = {}
    this.channel?.broadcast(this.toJSON(), 'deviceChanged')
  }

  private getComponentsInfo() {
    const res: any[] = []
    getSupportedComponents().forEach((componentName) => {
      const components = this.components[componentName]
      const count = components?.length || 0
      if (count > 1) {
        for (let i = 0; i < count; i++) {
          res.push({
            key: `${componentName}${i}`,
            name: componentName,
            id: i,
            settings: this.deviceSettings
              ? this.deviceSettings[`${componentName}${i}`] || {}
              : {}
          })
        }
      }
    })
    return res.length > 0 ? res : undefined
  }

  toJSON() {
    return {
      id: this.id,
      address: this.address,
      hostname: this.hostname,
      model: this.model,
      gen: this.gen,
      name: this.name,
      connected: this.connected,
      authFailed: this.authFailed,
      triedAuth: this.triedAuth,
      isConfigured: this.deviceSettings ? true : false,
      settings: this.deviceSettings || {},
      settingsCopy: this.deviceSettings || {},
      defaultPath: this.deviceSettings ? undefined : this.getDevicePath(),
      components: this.getComponentsInfo()
    }
  }

  /**
   * Manually trigger a reconnection attempt
   */
  forceReconnect() {
    if (this.connected) {
      this.debug(`Force reconnecting device ${this.id || this.address}`)
      this.disconnect()
    }

    this.shouldReconnect = true
    this.reconnectAttempts = 0
    this.attemptReconnection()
  }

  /**
   * Check if the device is currently attempting to reconnect
   */
  get reconnecting(): boolean {
    return this.isReconnecting
  }

  /**
   * Get the current reconnection attempt count
   */
  get reconnectionAttempts(): number {
    return this.reconnectAttempts
  }

  async send(method: string, params: any = {}): Promise<any> {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      this.attemptReconnection()
      throw new Error(
        `WebSocket is not connected (state: ${this.ws?.readyState || 'null'})`
      )
    }

    const id = this.next_id++
    const message = JSON.stringify({
      jsonrpc: '2.0',
      src: 'signalk-shelly2',
      id,
      method,
      params,
      auth: this.authMessage
    })

    try {
      this.ws.send(message)
    } catch (error) {
      throw new Error(`Failed to send WebSocket message: ${error}`)
    }

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        delete this.pendingRequests[id]
        reject(new Error(`Request ${id} for ${method} timed out`))
      }, 5000)

      this.pendingRequests[id] = {
        request: message,
        resolve,
        reject,
        timeout
      }
    })
  }

  async poll() {
    if (!this.connected) {
      // A failed (re)connect can leave the device here with nothing scheduled;
      // make sure a retry is pending rather than going silent forever.
      if (this.shouldReconnect && !this.isReconnecting) {
        this.attemptReconnection()
      }
      return
    }

    // Don't stack requests on a device that is slow to answer.
    if (this.polling) {
      return
    }
    this.polling = true

    try {
      const status = await this.send('Shelly.GetStatus')
      this.pollFailures = 0
      this.sendDeltas(status)
    } catch (error) {
      // One slow reply over Wi-Fi is not a dead connection (and the device keeps
      // pushing NotifyStatus meanwhile). Only reconnect after repeated failures.
      this.pollFailures++
      if (this.pollFailures >= 3) {
        this.pollFailures = 0
        this.reconnect()
      }
      throw error
    } finally {
      this.polling = false
    }
  }

  // Tear down the current socket and schedule a fresh connection.
  private reconnect() {
    this.debug(`Reconnecting to unresponsive device ${this.id || this.address}`)
    this.connected = false
    this.authMessage = undefined
    this.dropSocket()
    this.shouldReconnect = true
    this.isReconnecting = false
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout)
      this.reconnectTimeout = null
    }
    this.reconnectAttempts = 0
    this.attemptReconnection()
  }

  // Close a socket without triggering its close/error handlers.
  private dropSocket() {
    if (this.ws) {
      const ws = this.ws
      this.ws = null
      ws.removeAllListeners()
      ws.on('error', () => {})
      ws.terminate()
    }
    Object.values(this.pendingRequests).forEach((request) => {
      clearTimeout(request.timeout)
      request.reject(new Error('Connection reset'))
    })
    this.pendingRequests = {}
  }

  getCapabilities(status: any) {
    this.components = {}
    getSupportedComponents().forEach((name) => {
      Object.keys(status)
        .filter((key) => key.startsWith(`${name}:`))
        .forEach((key) => {
          const index = parseInt(key.split(':')[1])
          if (!isNaN(index)) {
            const component = createComponent(name, this, index)
            if (component) {
              if (this.components[name] === undefined) {
                this.components[name] = []
              }
              this.components[name].push(component)
            }
          }
        })
    })
  }

  getMainComponent(): Component | null {
    for (const component of Object.keys(this.components)) {
      if (this.components[component].length > 0) {
        return this.components[component][0]
      }
    }
    return null
  }

  getDevicePath(key?: string): Path {
    const component = this.getMainComponent()
    const deviceRoot =
      component != null ? component.skPath : 'electrical.unknown'
    let name = this.deviceSettings?.devicePath
    if (name !== undefined && name.indexOf('.') === -1) {
      name = `${deviceRoot}.${name}`
    } else if (name === undefined) {
      name = `${deviceRoot}.${this.name ? camelCase(this.name) : this.id}`
    }
    return `${name}${key ? '.' + key : ''}` as Path
  }

  getComponentProps(component: string, relay: number) {
    return this.deviceSettings
      ? this.deviceSettings[`${component}${relay}`]
      : undefined
  }

  async resendDeltas() {
    const result = await this.send('Shelly.GetStatus')
    this.sendDeltas(result)
  }

  sendDeltas(status: any) {
    let values: PathValue[] = []

    if (
      this.deviceSettings === undefined ||
      this.deviceSettings?.enabled === false
    ) {
      return
    }

    if (!this.sentMeta) {
      this.sendMeta()
      this.sentMeta = true
    }

    if (this.sentStaticDeltas === false) {
      if (this.name) {
        values.push({
          path: this.getDevicePath('name'),
          value: this.name
        })
      }

      if (this.model) {
        values.push({
          path: this.getDevicePath('model'),
          value: this.model
        })
      }

      values.push({
        path: this.getDevicePath('address'),
        value: this.address
      })

      if (this.id) {
        values.push({
          path: this.getDevicePath('id'),
          value: this.id
        })
      }

      if (this.hostname) {
        values.push({
          path: this.getDevicePath('hostname'),
          value: this.hostname
        })
      }

      this.sentStaticDeltas = true
    }

    Object.values(this.components).forEach((components) => {
      components.forEach((component) => {
        const componentProps = this.getComponentProps(
          component.componentName,
          component.componentId
        )

        if (componentProps?.enabled === false) {
          return
        }

        values = [...values, ...component.getDeltaValues(status)]
      })
    })

    if (values.length > 0) {
      this.debug('sending deltas %j', values)
      this.app.handleMessage(this.plugin.id + '.' + this.id, {
        updates: [
          {
            $source: (this.plugin.id + '.' + this.id) as SourceRef,
            values
          }
        ]
      })
    }
  }

  sendMeta() {
    let meta: any = []

    const devicePath = this.getDevicePath()

    if (this.deviceSettings?.enabled === false) {
      return
    }

    if (this.deviceSettings?.displayName || this.name) {
      meta.push({
        path: devicePath,
        value: {
          displayName: this.deviceSettings?.displayName || this.name
        }
      })
    }

    Object.values(this.components).forEach((components) => {
      components.forEach((component) => {
        const componentProps = this.getComponentProps(
          component.componentName,
          component.componentId
        )

        if (componentProps?.enabled === false) {
          return
        }

        meta = [...meta, ...component.getMeta()]
      })
    })

    if (meta.length) {
      this.debug('sending meta: %j', meta)
      this.app.handleMessage(this.plugin.id + '.' + this.id, {
        updates: [
          {
            $source: (this.plugin.id + '.' + this.id) as SourceRef,
            meta
          }
        ]
      })
    }
  }

  registerForPuts() {
    if (
      this.deviceSettings === undefined ||
      this.deviceSettings?.enabled === false
    ) {
      return
    }

    Object.values(this.components).forEach((components) => {
      components.forEach((component) => {
        const componentProps = this.getComponentProps(
          component.componentName,
          component.componentId
        )

        if (componentProps?.enabled === false) {
          return
        }

        component.registerPuts(this.app)
      })
    })
  }
}

class SendError extends Error {
  code: number
  constructor(message: string, code: number) {
    super(message)
    this.code = code
  }
}
