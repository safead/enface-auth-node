const uuid = require( 'uuid' );
const WebSocket = require( 'ws' );
const constants = require( './constants' );
const utils = require( './utils' );

export class EnfaceAuth {
  constructor( {
    debug,
    httpServer,
    port,
    projectId,
    secretCode,
    callbackUrl,
    onCheckCurrentStatus,
    onUserValidate,
    onActivate,
    onUserTokenByBioId
  } ) {
    this._DEBUG = !!debug;
    this.projectId = projectId;
    this.secretCode = Buffer.from( secretCode, 'base64' );
    this.callbackUrl = callbackUrl;
    this.callbackUrl.endsWith( '/' )
    && ( this.callbackUrl = this.callbackUrl.substring( 0, this.callbackUrl.length - 1 ) );
    this.onUserValidate = onUserValidate;
    this.onCheckCurrentStatus = onCheckCurrentStatus;
    this.onActivate = onActivate;
    this.onUserTokenByBioId = onUserTokenByBioId;
    this.wsServer = null;
    this.sessions = {};

    if ( httpServer ) {
      if ( port ) {
        console.error( `[EnfaceAuth constructor error]: 
        Please specify "server" for http(s) mode either "port" for ws(s) mode` );
        return;
      }
      this.callbackUrl += constants.HTTP_URI;
      this.log( '[EnfaceAuth constructor] Using HTTP/S server' );
      httpServer
        .post( constants.HTTP_URI, ( req, res ) => {
          this.log( `[EnfaceAuth] POST REQUEST', ${req.path}, ${req.body}` );
          this.newClient( { client: res } );
          utils.enfaceCors( res );
          if ( req.body instanceof Object ) {
            this.request( { client: res, data: JSON.stringify( req.body ) } );
          } else {
            let message = '';
            req.on( 'data', chunk => {
              message += chunk.toString();
            } );
            req.on( 'end', () => {
              this.request( { client: res, data: message } );
            } );
          }
        } )
        .options( async ( req, res ) => {
          utils.enfaceCors( res );
          res.end();
        } );
    } else {
      this.log( `[EnfaceAuth] Using sockets on port ${port}` );
      this.wsServer = new WebSocket.Server( { port } );
      this.wsServer.on( 'connection', socket => {
        this.newClient( { client: socket } );
        socket.on( 'message', data => {
          this.request( { client: socket, data } );
        } );
        socket.on( 'close', code => {
          this.log( `[EnfaceAuth] socket ${socket.clientId} closed with code: ${code}` );
          socket.isAlive = false;
        } );
        socket.isAlive = true;
        socket.on( 'pong', () => { socket.isAlive = true; } );
      } );
      setInterval( () => {
        this.wsServer.clients.forEach( socket => {
          if ( socket.isAlive === false ) {
            socket.terminate();
            return;
          }
          socket.isAlive = false;
          socket.ping( utils.noop );
        } );
      }, 30000 );
    }
  }

  log( value ) {
    this._DEBUG && console.log( value );
  }

  logError( value ) {
    this._DEBUG && console.error( value );
  }

  async request( { client, data } ) {
    this.log( `[EnfaceAuth.request], ${data}` );
    try {
      const { response, closeConnection } = await this.readMessage( { client, data } );
      this.send( {
        client,
        data: response
      } );
      closeConnection && this.finalizeSession( client );
    } catch ( error ) {
      this.logError( `[EnfaceAuth.request]', ${error.message}` );
      this.errorResponse( { client, message: error } );
      this.finalizeSession( client );
    }
  }

  send( { client, data } ) {
    this.log( `[EnfaceAuth.send], ${JSON.stringify( data )}` );
    if ( this.wsServer ) {
      client.send( JSON.stringify( data ) );
    } else {
      client.end( JSON.stringify( data ) );
    }
  }

  readMessage( { client, data } ) {
    return new Promise( resolve => {
      this.log( `[EnfaceAuth.readMessage] data, ${JSON.stringify( data )}, client.clientId, ${client.clientId}` );
      this.sessions[ client.clientId ].resolver = resolve;
      try {
        data = JSON.parse( data );
      } catch ( error ) {
        this.logError( `[EnfaceAuth.readMessage], ${error.message}` );
        return this.errorResponse( { client, message: `Wrong data received ${data}` } );
      }
      switch ( data._ ) {
        case constants.COMMAND_STATUS:
          return this.responseStatus( { client, userData: data.userData } );
        case constants.COMMAND_ENABLE:
        case constants.COMMAND_AUTH:
          return this.responseInit( { client, data } );
        case constants.COMMAND_CHECK:
          return this.responseCheck( { client, sessionId: data.sessionId } );
        case constants.COMMAND_BIO_ENABLE:
          return this.responseBioEnable( { client, data } );
        case constants.COMMAND_BIO_AUTH:
          return this.responseBioAuth( { client, data } );
        default:
          return this.errorResponse( { client, message: `Unknown command ${ data._ }` } );
      }
    } );
  }

  newClient( { client } ) {
    this.log( '[EnfaceAuth.newClient]' );
    const clientId = uuid();
    this.sessions[ clientId ] = {
      client,
      sessionId: uuid(),
      activated: false,
      userId: null,
      resolver: null
    };
    client.clientId = clientId;
    setTimeout( () => {
      this.finalizeSession( { clientId } );
    }, constants.AUTHORIZATION_TIME_FRAME );
  }

  switchSession( { client, clientId } ) {
    this.log( `[EnfaceAuth.switchSession] to clientId, ${clientId}` );
    if ( !this.sessions[ clientId ] ) {
      return this.errorResponse( { client, message: `Failed to get session params for client ${clientId}` } );
    }
    this.sessions[ client.clientId ]
    && delete this.sessions[ client.clientId ].client;
    this.sessions[ clientId ].resolver = this.sessions[ client.clientId ].resolver;
    this.finalizeSession( { clientId: client.clientId } );
    client.clientId = clientId;
    return true;
  }

  async responseInit( { client, data } ) {
    this.log( `[EnfaceAuth.responseInit] data, ${data}` );
    if ( !this.wsServer && data.clientId ) { // http server mode
      return this.switchSession( { client, clientId: data.clientId } );
    }
    const result = data._ === constants.COMMAND_ENABLE
      ? await this.linkSessionToUser( { client, userData: data.userData } )
      : true;
    if ( !result ) {
      return this.errorResponse( { client, message: `Failed to identify user with token: ${data.userData}` } );
    }
    const clientId = !this.wsServer
      ? client.clientId
      : undefined;
    return this.resolve( {
      client,
      data: {
        _: data._,
        token: utils.encrypt(
          [ this.sessions[ client.clientId ].sessionId, this.callbackUrl, data._ ].join( '|' ),
          this.secretCode
        ),
        id: this.projectId,
        clientId
      }
    } );
  }

  async responseStatus( { client, userData } ) {
    try {
      this.log( `[EnfaceAuth.responseStatus] userData, ${userData}` );
      const userId = await this.onUserValidate( userData );
      this.log( `[EnfaceAuth.responseStatus] user validated, userId: ${userId}` );
      const result = await this.onCheckCurrentStatus( userId );
      return this.finalResponse( {
        client,
        data: {
          _: constants.COMMAND_STATUS,
          check: true,
          isActive: result
        }
      } );
    } catch ( error ) {
      this.logError( '[EnfaceAuth.responseStatus] error', error );
      return this.errorResponse( { client, message: `Failed to validate user. Received token: ${userData}` } );
    }
  }

  responseCheck( { client, sessionId } ) {
    this.log( `[EnfaceAuth.responseCheck], sessionId, ${sessionId}` );
    const session = this.findSessionById( sessionId );
    if ( !session ) return this.errorResponse( { client, message: 'Client not found' } );
    if ( session.activated ) return this.errorResponse( { client, message: 'Client already activated' } );
    session.activated = true;
    return this.resolve( {
      client,
      data: {
        _: constants.COMMAND_READY
      }
    } );
  }

  async responseBioEnable( { client, data } ) {
    this.log( `[EnfaceAuth.responseBioEnable] sessionId, bioId, ${data.sessionId}, ${data.bioId}` );
    const session = this.findSessionById( data.sessionId );
    if ( !session ) return this.errorResponse( { client, message: 'Client not found' } );
    if ( !session.userId ) {
      return [ session.client, client ].forEach( item => {
        this.errorResponse( { client: item, message: 'User id is not assigned.' } );
      } );
    }
    if ( !data.bioId || !utils.isUuid( data.bioId ) ) {
      return [ session.client, client ].forEach( item => {
        return this.errorResponse( { client: item, message: 'Bad biometric id.' } );
      } );
    }
    const isActive = await this.onActivate( session.userId, data.bioId );
    this.log( `finalResponse responseBioEnable activated, ${isActive}` );
    return [ session.client, client ].forEach( item => {
      this.finalResponse( {
        client: item,
        data: {
          _: constants.COMMAND_STATUS,
          isActive
        }
      } );
    } );
  }

  async responseBioAuth( { client, data } ) {
    this.log( `[EnfaceAuth.responseBioAuth] sessionId, bioId, ${data.sessionId}, ${data.bioId}` );
    const session = this.findSessionById( data.sessionId );
    if ( !session ) return this.errorResponse( { client, message: 'Client not found.' } );
    if ( session.userId ) {
      return [ session.client, client ].forEach( item => {
        return this.errorResponse( { client: item, message: 'Client has wrong parameters.' } );
      } );
    }
    if ( !data.bioId || !utils.isUuid( data.bioId ) ) {
      return [ session.client, client ].forEach( item => {
        return this.errorResponse( { client: item, message: 'Bad biometric id.' } );
      } );
    }
    const token = await this.onUserTokenByBioId( data.bioId );
    this.log( `finalResponse responseBioAuth, ${token}` );
    this.finalResponse( {
      client,
      data: {
        _: constants.COMMAND_BIO_AUTH,
        result: !!token
      }
    } );
    this.finalResponse( {
      client: session.client,
      data: {
        _: constants.COMMAND_TOKEN,
        token
      }
    } );
  }

  async linkSessionToUser( { client, userData } ) {
    this.log( '[linkSessionToUser]', this );
    try {
      const userId = await this.onUserValidate( userData );
      this.log( `[linkSessionToUser] userId, ${userId}` );
      this.sessions[ client.clientId ].userId = userId;
      return true;
    } catch ( error ) {
      return false;
    }
  }

  errorResponse( { client, message } ) {
    this.logError( `[EnfaceAuth.errorResponse], ${message}` );
    this.finalResponse( {
      client,
      data: {
        _: constants.COMMAND_ERROR,
        message
      }
    } );
    return false;
  }

  finalResponse( { client, data } ) {
    this.log( `[EnfaceAuth.finalResponse], ${data}` );
    this.resolve( { client, data, closeConnection: true } );
  }

  resolve( { client, data, closeConnection } ) {
    this.log( `[EnfaceAuth.resolve] client.clientId, data, ${client.clientId}, ${data}` );
    const session = this.sessions[ client.clientId ];
    if ( !session || !session.resolver ) {
      if ( this.wsServer ) {
        this.send( { client: session.client, data } );
        closeConnection && this.closeClient( { client: session.client } );
      }
      return;
    }
    session.resolver( { response: data, closeConnection: !!closeConnection } );
    delete session.resolver;
  }

  finalizeSession( { clientId } ) {
    this.log( `[EnfaceAuth.finalizeSession] clientId ${clientId}` );
    this.sessions[ clientId ]
    && this.closeClient( { client: this.sessions[ clientId ].client } );
    delete this.sessions[ clientId ];
  }

  closeClient( { client } ) {
    this.log( `[EnfaceAuth.closeClient] client, ${!!client}` );
    if ( !client ) return;
    if ( this.wsServer ) {
      client.terminate();
    } else {
      try {
        client.end( 'timeout' );
      } catch ( error ) {
        this.logError( `[closeClient.error], ${error.message}` );
      }
    }
  }

  findSessionById( sessionId ) {
    for ( const value of Object.values( this.sessions ) ) {
      if ( value.sessionId === sessionId ) return value;
    }
    return null;
  }
}
