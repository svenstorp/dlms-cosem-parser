export class MeterDataHeader {
  encoding: string = 'A-XDR';
  frameFormat: number = 0;
  segmentation: number = 0;
  datalength: number = 0;
  client: number = 0;
  server: number = 0;
  control: number = 0;
  hcs: number = 0;
  fcs: number = 0;
  datetime: string = '';
}

export class MeterData {
  header: MeterDataHeader = new MeterDataHeader();
  payload: any[] = [];
}
