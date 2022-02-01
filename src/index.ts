import { MeterData } from './meterdata';
import { Subject } from 'rxjs';
import { crc } from 'polycrc';

class DLMSCOSEMParser {
  private readonly MaxBufferSize = 2048;
  private readonly AXDRStartStopFlag = 0x7e;
  private buff: Buffer = Buffer.alloc(0);
  private currentOffset: number = 0;
  private currentMeterData: MeterData = new MeterData();

  public parsedDataAvailable: Subject<MeterData> = new Subject<MeterData>();

  pushData(d: Buffer) {
    // Check if buffer is overful, and should be truncated
    if (this.buff.length + d.length > this.MaxBufferSize) {
      this.buff = Buffer.alloc(0);
    }

    this.buff = Buffer.concat([this.buff, d]);

    this.parseBuffer();
  }

  result(): MeterData {
    return this.currentMeterData;
  }

  private parseBuffer() {
    let startOffset = 0;

    if (this.buff.length < 3) {
      return;
    }

    // Search for start offset
    while (startOffset < this.buff.length) {
      if (this.buff[startOffset++] == this.AXDRStartStopFlag) {
        break;
      }
    }

    if (startOffset >= this.buff.length) {
      return;
    }

    // Sometimes there are duplicated start flags, strip out first
    while (this.buff[startOffset] == this.AXDRStartStopFlag && startOffset < this.buff.length) {
      startOffset++;
    }

    if (startOffset + 14 >= this.buff.length) {
      return;
    }

    this.currentOffset = startOffset;

    // Parse frame info
    const frameInfo = { frameFormat: 0, dataLength: -1, segmentation: false };
    this.frameFormatLength(frameInfo);

    // If we haven't received enough data yet, return
    if (startOffset + frameInfo.dataLength >= this.buff.length) {
      return;
    }

    // Get addresses
    const clientAddr = this.parseAddress();
    const serverAddr = this.parseAddress();
    const control = this.buff[this.currentOffset++];

    // CRC calculation
    const headerCRC = (this.buff[this.currentOffset + 1] << 8) | this.buff[this.currentOffset];
    const frameCRC =
      (this.buff[startOffset + frameInfo.dataLength - 2 + 1] << 8) | this.buff[startOffset + frameInfo.dataLength - 2];

    const crc16 = crc(16, 0x1021, 0xffff, 0xffff, true);
    if (headerCRC != crc16(this.buff.slice(startOffset, this.currentOffset))) {
      console.warn('Invalid header CRC'); // TODO: use a log library?
      // Skip up to byte after startbyte (and we will start searching from there next time)
      this.buff = this.buff.slice(startOffset, undefined);
      return;
    }

    if (frameCRC != crc16(this.buff.slice(startOffset, startOffset + frameInfo.dataLength - 2))) {
      console.warn('Invalid frame CRC'); // TODO: use a log library?
      // Skip up to byte after startbyte (and we will start searching from there next time)
      this.buff = this.buff.slice(startOffset, undefined);
      return;
    }

    this.currentOffset += 2;

    // LLC (skip)
    startOffset = this.currentOffset;
    this.currentOffset += 3;

    // APDU
    this.currentOffset++;
    startOffset = this.currentOffset;
    this.currentOffset += 4;

    // Initialize JSON object
    const dataObject: MeterData = new MeterData();

    dataObject.header.frameFormat = frameInfo.frameFormat;
    dataObject.header.segmentation = frameInfo.segmentation ? 1 : 0;
    dataObject.header.datalength = frameInfo.dataLength;
    dataObject.header.client = clientAddr;
    dataObject.header.server = serverAddr;
    dataObject.header.control = control;
    dataObject.header.hcs = headerCRC;
    dataObject.header.fcs = frameCRC;

    // Parse date / time (length 0 or 12)
    for (let i = 0; i < 12; i++, this.currentOffset++) {
      if (this.buff[this.currentOffset] == 0 || this.buff[this.currentOffset] == 0x0c) {
        break;
      }
    }
    dataObject.header.datetime = this.buff
      .slice(this.currentOffset, this.currentOffset + this.buff[this.currentOffset] + 1)
      .toString('hex');
    this.currentOffset += this.buff[this.currentOffset] + 1;

    dataObject.payload = this.parsePayload();

    if (this.currentOffset + 2 < this.buff.length) {
      this.buff = this.buff.slice(this.currentOffset + 2, undefined);
    } else {
      this.buff = Buffer.alloc(0);
    }
    this.currentOffset = 0;

    if (dataObject.payload !== undefined) {
      this.currentMeterData = dataObject;
      this.parsedDataAvailable.next(dataObject);
    }
  }

  private parsePayload(): any {
    const retMap: Map<string, any> = new Map<string, any>();
    let n = 0;

    switch (this.buff[this.currentOffset++]) {
      case 0: // null data
        break;
      case 1: // array
      // Intentionally fall through
      case 2: {
        // structure
        n = this.buff[this.currentOffset + 1];
        if (n == 1 || n == 2 || n == 19) {
          for (n = this.buff[this.currentOffset++]; n > 0; --n) {
            const retVal = this.parsePayload();
            if (retVal === undefined) {
              return undefined;
            }
            retVal.forEach((value: any, key: string) => {
              retMap.set(key, value);
            });
          }
        } else {
          let keyName: string = '';
          if (n == 10) {
            n = this.buff[this.currentOffset++] - 1;
            this.currentOffset += 2;
            keyName = this.buff
              .slice(this.currentOffset, this.currentOffset + this.buff[this.currentOffset - 1])
              .toString('ascii');
            this.currentOffset += this.buff[this.currentOffset - 1];
          } else if (n == 9) {
            n = this.buff[this.currentOffset++] - 1;
            this.currentOffset += 2;
            keyName = this.formatOBISCode(
              this.buff.slice(this.currentOffset, this.currentOffset + this.buff[this.currentOffset - 1]),
            );
            this.currentOffset += this.buff[this.currentOffset - 1];
          } else {
            n = this.buff[this.currentOffset++];
            keyName = 'data';
          }
          let entryArr: any[] = [];
          while (n > 0) {
            const tmpVal = this.parseEntry();
            if (tmpVal === undefined) {
              return undefined;
            }
            entryArr.push(tmpVal);
            n--;
          }
          entryArr = this.convertKnownData(keyName, entryArr);
          entryArr = this.parseClass3Value(entryArr);
          retMap.set(keyName, entryArr);
        }
        break;
      }
      case 19: // compact array
        return undefined; // TODO
      default:
        return undefined;
    }

    return retMap;
  }

  private parseEntry(): any {
    // Entry definitions on IEC 62056-6-2 Table 2
    let retVal: any;

    switch (this.buff[this.currentOffset++]) {
      case 0: // NULL data
        break;
      case 1: // array
      // Intentionally fall through
      case 2: {
        // structure
        const entryArr: any[] = [];
        for (let i = this.buff[this.currentOffset++]; i > 0; i--) {
          const tmpVal = this.parseEntry();
          if (tmpVal === undefined) {
            return undefined;
          }
          entryArr.push(tmpVal);
        }
        retVal = entryArr;
        break;
      }
      case 3: // boolean
        retVal = this.buff[this.currentOffset++] != 0 ? true : false;
        break;
      case 4: // bit-string
        retVal = this.generateBitString(this.buff[this.currentOffset++]);
        break;
      case 5: // int32
        const int32val: Int32Array = new Int32Array(1);
        int32val[0] =
          (this.buff[this.currentOffset] << 24) |
          (this.buff[this.currentOffset + 1] << 16) |
          (this.buff[this.currentOffset + 2] << 8) |
          this.buff[this.currentOffset + 3];
        retVal = int32val[0];
        this.currentOffset += 4;
        break;
      case 6: // uint32
        retVal =
          (this.buff[this.currentOffset] << 24) |
          (this.buff[this.currentOffset + 1] << 16) |
          (this.buff[this.currentOffset + 2] << 8) |
          this.buff[this.currentOffset + 3];
        this.currentOffset += 4;
        break;
      case 9: {
        // octet-string
        const n = this.buff[this.currentOffset++];
        retVal = this.buff.slice(this.currentOffset, this.currentOffset + n).toString('hex');
        this.currentOffset += n;
        break;
      }
      case 10: {
        // visible-string
        const n = this.buff[this.currentOffset++];
        retVal = this.buff.slice(this.currentOffset, this.currentOffset + n).toString('ascii');
        this.currentOffset += n;
        break;
      }
      case 12: {
        // utf8-string
        const n = this.buff[this.currentOffset++];
        retVal = this.buff.slice(this.currentOffset, this.currentOffset + n).toString('utf-8');
        this.currentOffset += n;
        break;
      }
      case 13: // bcd int8
        retVal = this.buff.slice(this.currentOffset, this.currentOffset + 1).toString('hex');
        this.currentOffset++;
        break;
      case 15: // int8
        const int8Val: Int8Array = new Int8Array(1);
        int8Val[0] = this.buff[this.currentOffset++];
        retVal = int8Val[0];
        break;
      case 16: // int16
        const int16Val: Int16Array = new Int16Array(1);
        int16Val[0] = (this.buff[this.currentOffset] << 8) | this.buff[this.currentOffset + 1];
        retVal = int16Val[0];
        this.currentOffset += 2;
        break;
      case 17: // uint8
        retVal = this.buff[this.currentOffset++];
        break;
      case 18: // uint16
        retVal = (this.buff[this.currentOffset] << 8) | this.buff[this.currentOffset + 1];
        this.currentOffset += 2;
        break;
      case 19: // compact array
        // TODO
        break;
      case 20: // int64
        retVal = BigInt(
          (this.buff[this.currentOffset] << 56) |
            (this.buff[this.currentOffset + 1] << 48) |
            (this.buff[this.currentOffset + 2] << 40) |
            (this.buff[this.currentOffset + 3] << 32) |
            (this.buff[this.currentOffset + 4] << 24) |
            (this.buff[this.currentOffset + 5] << 16) |
            (this.buff[this.currentOffset + 6] << 8) |
            this.buff[this.currentOffset + 7],
        );
        this.currentOffset += 8;
        break;
      case 21: // uint64
        retVal = BigInt(
          (this.buff[this.currentOffset] << 56) |
            (this.buff[this.currentOffset + 1] << 48) |
            (this.buff[this.currentOffset + 2] << 40) |
            (this.buff[this.currentOffset + 3] << 32) |
            (this.buff[this.currentOffset + 4] << 24) |
            (this.buff[this.currentOffset + 5] << 16) |
            (this.buff[this.currentOffset + 6] << 8) |
            this.buff[this.currentOffset + 7],
        );
        this.currentOffset += 8;
        break;
      case 22: // enum len = 1
        retVal = this.toEnumString(this.buff[this.currentOffset++]);
        break;
      case 23: // float 32-bit
        // TODO
        break;
      case 24: // float 64-bit
        // TODO
        break;
      case 25: // date/time octet-string len = 12
        retVal = this.buff.slice(this.currentOffset, this.currentOffset + 12).toString('hex');
        this.currentOffset += 12;
        break;
      case 26: // date octet-string len = 5
        retVal = this.buff.slice(this.currentOffset, this.currentOffset + 5).toString('hex');
        this.currentOffset += 5;
        break;
      case 27: // time octet-string len = 4
        retVal = this.buff.slice(this.currentOffset, this.currentOffset + 4).toString('hex');
        this.currentOffset += 4;
        break;
      default:
        break;
    }

    return retVal;
  }

  private frameFormatLength(result: { frameFormat: number; dataLength: number; segmentation: boolean }) {
    // Frame format (IEC13239 4.9)
    result.frameFormat = (this.buff[this.currentOffset] & 0x80) >> 7;

    if (this.buff[this.currentOffset] <= 0x7f) {
      result.dataLength = this.buff[this.currentOffset++] & 0x7f;
    } else if (this.buff[this.currentOffset] <= 0xf0) {
      result.frameFormat += (this.buff[this.currentOffset] & 0x70) >> 4;
      result.segmentation = (this.buff[this.currentOffset] & 0x08) != 0;
      result.dataLength = (this.buff[this.currentOffset++] & 0x07) << 8;
      result.dataLength += this.buff[this.currentOffset++];
    } else {
      result.frameFormat = 8;
    }

    return result;
  }

  private parseAddress(): number {
    let addr = 0;

    for (let i = 0; i < 4; i++) {
      addr = (addr << 8) | this.buff[this.currentOffset++];
      if ((addr & 0x01) != 0) {
        break;
      }
    }

    return addr;
  }

  private formatOBISCode(data: Buffer): string {
    if (data.length == 5) {
      return (
        data[0].toString() +
        '-' +
        data[1].toString() +
        ':' +
        data[2].toString() +
        '.' +
        data[3].toString() +
        '.' +
        data[4].toString()
      );
    } else if (data.length == 6) {
      return (
        data[0].toString() +
        '-' +
        data[1].toString() +
        ':' +
        data[2].toString() +
        '.' +
        data[3].toString() +
        '.' +
        data[4].toString() +
        '.' +
        data[5].toString()
      );
    } else {
      return data.toString('ascii');
    }
  }

  private parseClass3Value(entry: any[]): any[] {
    if (entry.length != 2 || entry[1] === undefined || entry[1].length != 2) {
      return entry;
    }

    const retArr: any[] = [];
    retArr[0] = entry[0] * Math.pow(10, entry[1][0]);
    retArr[1] = entry[1][1];

    return retArr;
  }

  private leftPad(num: number, targetLength: number): string {
    let output = num + '';
    while (output.length < targetLength) {
      output = '0' + output;
    }
    return output;
  }

  private convertKnownData(keyName: string, entry: any[]): any[] {
    switch (keyName) {
      case '0-0:1.0.0.255':
        const binData: Buffer = Buffer.from(entry[0], 'hex');
        entry[0] =
          '' +
          ((binData[0] << 8) + binData[1]) +
          '-' +
          this.leftPad(binData[2], 2) +
          '-' +
          this.leftPad(binData[3], 2) +
          ' ' +
          this.leftPad(binData[5], 2) +
          ':' +
          this.leftPad(binData[6], 2) +
          ':' +
          this.leftPad(binData[7], 2);
        return entry;
      default:
        return entry;
    }
  }

  private generateBitString(byteVal: number): string {
    return byteVal & 0x80
      ? '1'
      : '0' + (byteVal & 0x40)
      ? '1'
      : '0' + (byteVal & 0x20)
      ? '1'
      : '0' + (byteVal & 0x10)
      ? '1'
      : '0' + (byteVal & 0x08)
      ? '1'
      : '0' + (byteVal & 0x04)
      ? '1'
      : '0' + (byteVal & 0x02)
      ? '1'
      : '0' + (byteVal & 0x01)
      ? '1'
      : '0';
  }

  private toEnumString(enumVal: number): string {
    switch (enumVal) {
      case 1:
        return 'a'; // year
      case 2:
        return 'mo';
      case 3:
        return 'wk';
      case 4:
        return 'd';
      case 5:
        return 'h';
      case 6:
        return 'min';
      case 7:
        return 's';
      case 8:
        return '°';
      case 9:
        return '°C';
      case 10:
        return '€';
      case 11:
        return 'm';
      case 12:
        return 'm/s';
      case 13:
        return 'm';
      case 14:
        return 'm³';
      case 15:
        return 'm³/h';
      case 16:
        return 'm³/h';
      case 17:
        return 'm³/d';
      case 18:
        return 'm³/d';
      case 19:
        return 'l';
      case 20:
        return 'kg';
      case 21:
        return 'N';
      case 22:
        return 'Nm';
      case 23:
        return 'Pa';
      case 24:
        return 'bar';
      case 25:
        return 'J';
      case 26:
        return 'J/h';
      case 27:
        return 'W';
      case 28:
        return 'VA';
      case 29:
        return 'var';
      case 30:
        return 'Wh';
      case 31:
        return 'VAh';
      case 32:
        return 'varh';
      case 33:
        return 'A';
      case 34:
        return 'C';
      case 35:
        return 'V';
      case 36:
        return 'V/m';
      case 37:
        return 'F';
      case 38:
        return 'Ω';
      case 39:
        return 'Ωm²/m';
      case 40:
        return 'Wb';
      case 41:
        return 'T';
      case 42:
        return 'A/m';
      case 43:
        return 'H';
      case 44:
        return 'Hz';
      case 45:
        return '1/(Wh)';
      case 46:
        return '1/(varh)';
      case 47:
        return '1/(VAh)';
      case 48:
        return 'V²h';
      case 49:
        return 'A²h';
      case 50:
        return 'kg/s';
      case 51:
        return 'S';
      case 52:
        return '°K';
      case 53:
        return '1/(V²h)';
      case 54:
        return '1/(A²h)';
      case 55:
        return '1/m³';
      case 56:
        return '%';
      case 57:
        return 'Ah';
      case 60:
        return 'Wh/m³';
      case 61:
        return 'J/m³';
      case 62:
        return 'Mol%';
      case 63:
        return 'g/m³';
      case 64:
        return 'Pa s';
      case 65:
        return 'J/kg';
      case 70:
        return 'dBm';
      case 71:
        return 'dbμV';
      case 72:
        return 'dB';
      default:
        return '*';
    }
  }
}

export { DLMSCOSEMParser };
export * from './meterdata';
