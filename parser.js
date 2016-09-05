'use strict';

var inherits  = require('util').inherits,
    EE        = require('events').EventEmitter,
    Packet    = require('./packet'),
    constants = require('./constants');

function Parser(opts) {
  if (!(this instanceof Parser)) {
    return new Parser(opts);
  }
  
  opts = opts || {};

  this.buffer = null;
  this.packet = null;

  this._isClient = opts.isClient || false;

}

inherits(Parser, EE);

Parser.prototype.parse = function parserParse(buf) {
  this.buffer = buf;

  this.packet = new Packet();

  if(!this._parseHeader()) return null;
  if(!this._parsePayload()) return null;

  return this.packet;
};

Parser.prototype._parseHeader = function parserParseHeader() {
  var header = this._parseHeaderInternal(0);
  if (header === null) {
    return false;
  }

  this.packet.length = header.length;
  this.packet.cmd = constants.types[header.cmdCode];

  this.buffer = this.buffer.slice(header.headerLength);

  return true;
};

Parser.prototype._parseHeaderInternal = function parserParseHeaderInternal(pos) {
  var length = this.buffer.readUInt8(pos),
      cmdCodeOffset = 1;
  if (length === 0x01) {
    if (this.buffer.length < (pos + 4)) {
      return null;
    }
    
    length = this.buffer.readUInt16BE(pos + 1);
    cmdCodeOffset = 3;
  } else if (this.buffer.length < 2) {
    return null;
  }
  
  var cmdCode = this.buffer.readUInt8(pos + cmdCodeOffset);
  return {
    length: length - (cmdCodeOffset + 1),
    headerLength: cmdCodeOffset + 1,
    cmdCode: cmdCode
  };
};

Parser.prototype._parsePayload = function parserParsePayload() {
  var result = false;
  
  if ((this.packet.length === 0) ||
      (this.buffer.length >= this.packet.length)) {
    
    if (this.packet.cmd !== 'Encapsulated message') {
      switch (this.packet.cmd) {
        case 'advertise':
          return this._parseAdvertise();
          break;
        case 'searchgw':
          return this._parseSearchGW();
          break;
        case 'gwinfo':
          return this._parseGWInfo();
          break;
        case 'connect':
          return this._parseConnect();
          break;
        case 'connack':
        case 'willtopicresp':
        case 'willmsgresp':
          return this._parseRespReturnCode();
          break;
        case 'willtopicupd':
        case 'willtopic':
          return this._parseWillTopic();
          break;
        case 'willmsg':
        case 'willmsgupd':
          return this._parseWillMsg();
          break;
        case 'register':
          return this._parseRegister();
          break;
        case 'regack':
          return this._parseRegAck();
          break;
        case 'publish':
          return this._parsePublish();
          break;
        case 'puback':
          return this._parsePubAck();
          break;
        case 'pubcomp':
        case 'pubrec':
        case 'pubrel':
        case 'unsuback':
          return this._parseMsgId();
          break;
        case 'unsubscribe':
        case 'subscribe':
          return this._parseSubscribeUnsubscribe();
          break;
        case 'suback':
          return this._parseSubAck();
          break;
        case 'pingreq':
          return this._parsePingReq();
          break;
        case 'disconnect':
          return this._parseDisconnect();
          break;
        case 'willtopicreq':
        case 'willmsgreq':
        case 'pingresp':
          // these are empty, nothing to do
          break;
        default:
          this.emit('error', new Error('command not supported'));
          return false;
      }

      result = true;
    } else if (this.packet.cmd === 'Encasulated message') {
      result = this._parseEncapsulatedMsg();
    }
  }
  
  return result;
};

Parser.prototype._parseAdvertise = function parserParseAdvertise() {
  if (this.packet.length !== 3) {
    this.emit('error', new Error('wrong packet length'));
    return false;
  }
  
  this.packet.gwId = this.buffer.readUInt8(0);
  this.packet.duration = this.buffer.readUInt16BE(1);
  return true;
};

Parser.prototype._parseSearchGW = function parserParseSearchGW() {
  if (this.packet.length !== 1) {
    this.emit('error', new Error('wrong packet length'));
    return false;
  }
  
  this.packet.radius = this.buffer.readUInt8(0);
  return true;
};

Parser.prototype._parseGWInfo = function parserParseGWInfo() {
  if ((this._isClient && (this.packet.length < 2)) ||
      (!this._isClient && (this.packet.length !== 1))) {
    this.emit('error', new Error('wrong packet length'));
    return false;
  }
  
  this.packet.gwId = this.buffer.readUInt8(0);
  
  if (this._isClient) {
    var addLen = this.buffer.readUInt8(1);
    if (this.packet.length !== (2 + addLen)) {
      this.emit('error', new Error('wrong packet length'));
      return false;
    }
    
    this.packet.gwAdd = this.buffer.slice(2, this.packet.length);
  }
  return true;  
};

Parser.prototype._parseConnect = function parserParseConnect() {
  if (this.packet.length < 4) {
    this.emit('error', new Error('packet too short'));
    return false;
  }
  
  if (!this._parseFlags(this.buffer.readUInt8(0))) { return true; }
  if (this.buffer.readUInt8(1) !== constants.ID) {
    this.emit('error', new Error('unsupported protocol ID'));
    return false;
  }
  this.packet.duration = this.buffer.readUInt16BE(2);
  if (this.packet.length < 5) {
    if(this.packet.cleanSession) return true; // Allow blank client id according to standard
    else { this.emit('error', new Error('cannot read client ID')); return false; }
  }
  this.packet.clientId = this.buffer.toString('utf8', 4, this.packet.length);
  if (this.packet.clientId === null) {
    this.emit('error', new Error('cannot read client ID'));
    return false;
  }
  return true;
};

Parser.prototype._parseRespReturnCode = function parserParseRespReturnCode() {
  if (this.packet.length !== 1) {
    this.emit('error', new Error('wrong packet length'));
    return false;
  }
  
  this.packet.returnCode = this._parseReturnCode(this.buffer.readUInt8(0));
  return true;
};

Parser.prototype._parseWillTopic = function parserParseWillTopic() {
  if (this.packet.length !== 0) {
    if (!this._parseFlags(this.buffer.readUInt8(0))) { return true; }
    this.packet.willTopic = this.buffer.toString('utf8', 1, this.packet.length);
  }
  return true;
};

Parser.prototype._parseWillMsg = function parserParseWillMsg() {
  this.packet.willMsg = this.buffer.toString('utf8', 0, this.packet.length);
  return true;
};

Parser.prototype._parseRegister = function parserParseRegister() {
  if (this.packet.length < 4) {
    this.emit('error', new Error('packet too short'));
    return false;
  }
  
  this.packet.topicId = this.buffer.readUInt16BE(0);
  this.packet.msgId = this.buffer.readUInt16BE(2);
  this.packet.topicName = this.buffer.toString('utf8', 4, this.packet.length);
  return true;
};

Parser.prototype._parseRegAck = function parserParseRegAck() {
  if (this.packet.length !== 5) {
    this.emit('error', new Error('wrong packet length'));
    return false;
  }
  
  this.packet.topicId = this.buffer.readUInt16BE(0);
  this.packet.msgId = this.buffer.readUInt16BE(2);
  this.packet.returnCode = this._parseReturnCode(this.buffer.readUInt8(4));
  return true;
};

Parser.prototype._parsePublish = function parserParsePublish() {
  if (this.packet.length < 5) {
    this.emit('error', new Error('packet too short'));
    return false;
  }
  
  if (!this._parseFlags(this.buffer.readUInt8(0))) { return true; }
  if (this.packet.topicIdType === 'short topic') {
    this.packet.topicId = this.buffer.toString('utf8', 1, 3);
  } else {
    this.packet.topicId = this.buffer.readUInt16BE(1);
  }
  this.packet.msgId = this.buffer.readUInt16BE(3);
  this.packet.payload = this.buffer.slice(5, this.packet.length);
  return true;
};

Parser.prototype._parsePubAck = function parserParsePubAck() {
  if (this.packet.length !== 5) {
    this.emit('error', new Error('wrong packet length'));
    return false;
  }
  
  this.packet.topicId = this.buffer.readUInt16BE(0);
  this.packet.msgId = this.buffer.readUInt16BE(2);
  this.packet.returnCode = this._parseReturnCode(this.buffer.readUInt8(4));
  return true;
};

Parser.prototype._parseMsgId = function parserParseMsgId() {
  if (this.packet.length !== 2) {
    this.emit('error', new Error('wrong packet length'));
    return false;
  }
  
  this.packet.msgId = this.buffer.readUInt16BE(0);
  return true;
};

Parser.prototype._parseSubscribeUnsubscribe = function parserParseSubscribeUnsubscribe() {
  if (this.packet.length < 3) {
    this.emit('error', new Error('packet too short'));
    return false;
  }
  
  if (!this._parseFlags(this.buffer.readUInt8(0))) { return true; }
  this.packet.msgId = this.buffer.readUInt16BE(1);
  
  switch (this.packet.topicIdType) {
    case 'short name':
      if (this.packet.length !== 5) {
        this.emit('error', new Error('wrong packet length'));
        return false;
      }
      this.packet.topicName = this.buffer.toString('utf8', 3, this.packet.length);
      break;
    case 'normal':
      this.packet.topicName = this.buffer.toString('utf8', 3, this.packet.length);
      break;
    case 'pre-defined':
      if (this.packet.length !== 5) {
        this.emit('error', new Error('wrong packet length'));
        return false;
      }
      this.packet.topicId = this.buffer.readUInt16BE(3);
      break;
  }
  return true;
};

Parser.prototype._parseSubAck = function parserParseSubAck() {
  if (this.packet.length !== 6) {
    this.emit('error', new Error('wrong packet length'));
    return false;
  }
  
  if (!this._parseFlags(this.buffer.readUInt8(0))) { return true; }
  this.packet.topicId = this.buffer.readUInt16BE(1);
  this.packet.msgId = this.buffer.readUInt16BE(3);
  this.packet.returnCode = this._parseReturnCode(this.buffer.readUInt8(5));
  return true;
};

Parser.prototype._parsePingReq = function parserParsePingReq() {
  if (this.packet.length !== 0) {
    this.packet.clientId = this.buffer.toString('utf8', 0, this.packet.length);
  }
  return true;
};

Parser.prototype._parseDisconnect = function parserParseDisconnect() {
  if (this.packet.length !== 0) {
    if (this.packet.length === 2) {
      this.packet.duration = this.buffer.readUInt16BE(0);
    } else  {
      this.emit('error', new Error('wrong packet length'));
      return false;
    }
  }
  return true;
};

Parser.prototype._parseEncapsulatedMsg = function parserParseEncapsulatedMsg() {
  if (this.packet.length < 1) {
    this.emit('error', new Error('packet too short'));
    return false;
  }
  
  var ctrl = this.buffer.readUInt8(0);
  this.packet.radius = ctrl & constants.RADIUS_MASK;
  this.packet.wirelessNodeId = this.buffer.toString('utf8', 1, this.packet.length);
  
  var header = this._parseHeaderInternal(this.packet.length);
  if (header === null) {
    return false;
  }
  if (header.cmdCode === constants.codes['Encapsulated message']) {
    this.emit('error', new Error('nested encapsulated message is not supported'));
    return false;
  }
  if (this.buffer.length < (this.packet.length + header.length + header.headerLength)) {
    return false;
  }
  this.packet.length = this.packet.length + header.length + header.headerLength;
  this.packet.encapsulated = this.buffer.slice(this.packet.length, this.packet.length);
  
  return true;
};

Parser.prototype._parseReturnCode = function parserParseReturnCode(retCode) {
  return constants.return_types[retCode];
};

Parser.prototype._parseFlags = function parserParseFlags(flags) {
  var packet = this.packet,
      result = true;
  
  if ((packet.cmd === 'publish') ||
      (packet.cmd === 'subscribe')) {
    packet.dup = (flags & constants.DUP_MASK) === constants.DUP_MASK;
  }
  
  if ((packet.cmd === 'willtopic') ||
      (packet.cmd === 'publish') ||
      (packet.cmd === 'subscribe') ||
      (packet.cmd === 'suback')) {
    packet.qos = (flags & constants.QOS_MASK) >> constants.QOS_SHIFT;
  }
  
  if ((packet.cmd === 'willtopic') ||
      (packet.cmd === 'publish')) {
    packet.retain = (flags & constants.RETAIN_MASK) === constants.RETAIN_MASK;
  }
  if (packet.cmd === 'connect') {
    packet.will = (flags & constants.WILL_MASK) === constants.WILL_MASK;
    packet.cleanSession = (flags & constants.CLEAN_MASK) === constants.CLEAN_MASK;
  }
  if ((packet.cmd === 'publish') ||
      (packet.cmd === 'subscribe') ||
      (packet.cmd === 'unsubscribe')) {
    switch (flags & constants.TOPICIDTYPE_MASK) {
      case 0x00:
        packet.topicIdType = 'normal';
        break;
      case 0x01:
        packet.topicIdType = 'pre-defined';
        break;
      case 0x02:
        packet.topicIdType = 'short topic';
        break;
      default:
        this.emit('error', new Error('unsupported topic id type'));
        result = false;
    }
  }
  return result;
};

module.exports = Parser;
