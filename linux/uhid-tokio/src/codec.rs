use std::ffi;
use std::io;
use std::iter::repeat;
use std::mem;
use std::slice;

use bytes::BytesMut;
use slog;

use transport::{Decoder, Encoder};
use uhid_sys as sys;

quick_error! {
    #[derive(Debug)]
    pub enum StreamError {
        Io(err: io::Error) {
            from()
        }
        UnknownEventType(event_type_value: u32) {
            description("Unknown/Unsupported event type")
            display(r#"Unknown/Unsupported event type: "{}""#, event_type_value)
        }
        BufferOverflow(data_size: usize, max_size: usize) {
            description("Size exceeds available space.")
            display(r#"Size "{}" exceeds available space "{}""#, data_size, max_size)
        }
        Nul(err: ffi::NulError) {
            from()
        }
        Unknown
    }
}

bitflags! {
    pub struct DevFlags: u64 {
        const NUMBERED_FEATURE_REPORTS = 0b0000_0001;
        const NUMBERED_OUTPUT_REPORTS  = 0b0000_0010;
        const NUMBERED_INPUT_REPORTS   = 0b0000_0100;
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum ReportType {
    Feature = 0,
    Output = 1,
    Input = 2,
}

#[allow(non_camel_case_types)]
pub enum Bus {
    PCI = 1,
    ISAPNP = 2,
    USB = 3,
    HIL = 4,
    BLUETOOTH = 5,
    VIRTUAL = 6,
    ISA = 16,
    I8042 = 17,
    XTKBD = 18,
    RS232 = 19,
    GAMEPORT = 20,
    PARPORT = 21,
    AMIGA = 22,
    ADB = 23,
    I2C = 24,
    HOST = 25,
    GSC = 26,
    ATARI = 27,
    SPI = 28,
    RMI = 29,
    CEC = 30,
    INTEL_ISHTP = 31,
}

pub enum InputEvent {
    Create {
        name: String,
        phys: String,
        uniq: String,
        bus: Bus,
        vendor: u32,
        product: u32,
        version: u32,
        country: u32,
        data: Vec<u8>,
    },
    Destroy,
    Input {
        data: Vec<u8>,
    },
    GetReportReply {
        id: u32,
        err: u16,
        data: Vec<u8>,
    },
    SetReportReply {
        id: u32,
        err: u16,
    },
}

pub enum OutputEvent {
    Start {
        dev_flags: DevFlags,
    },
    Stop,
    Open,
    Close,
    Output {
        data: Vec<u8>,
    },
    GetReport {
        id: u32,
        report_number: u8,
        report_type: ReportType,
    },
    SetReport {
        id: u32,
        report_number: u8,
        report_type: ReportType,
        data: Vec<u8>,
    },
}

impl slog::Value for OutputEvent {
    fn serialize(
        &self,
        record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        match self {
            &OutputEvent::Start { .. } => "Start",
            &OutputEvent::Stop => "Stop",
            &OutputEvent::Open => "Open",
            &OutputEvent::Close => "Close",
            &OutputEvent::Output { .. } => "Output",
            &OutputEvent::GetReport { .. } => "GetReport",
            &OutputEvent::SetReport { .. } => "SetReport",
        }.serialize(record, key, serializer)
    }
}

#[derive(Debug, Default)]
pub struct Codec;

impl InputEvent {
    fn into_uhid_event(self) -> Result<sys::uhid_event, StreamError> {
        let mut event: sys::uhid_event = unsafe { mem::zeroed() };

        match self {
            InputEvent::Create {
                name,
                phys,
                uniq,
                bus,
                vendor,
                product,
                version,
                country,
                data,
            } => {
                event.type_ = sys::uhid_event_type_UHID_CREATE2 as u32;
                unsafe {
                    let payload = &mut event.u.create2;
                    copy_as_cstr(name, &mut payload.name)?;
                    copy_as_cstr(phys, &mut payload.phys)?;
                    copy_as_cstr(uniq, &mut payload.uniq)?;
                    payload.rd_size = copy_bytes_sized(data, &mut payload.rd_data)? as u16;
                    payload.bus = bus as u16;
                    payload.vendor = vendor;
                    payload.product = product;
                    payload.version = version;
                    payload.country = country;
                }
            }
            InputEvent::Destroy => {
                event.type_ = sys::uhid_event_type_UHID_DESTROY as u32;
            }
            InputEvent::Input { data } => {
                event.type_ = sys::uhid_event_type_UHID_INPUT2 as u32;
                unsafe {
                    let payload = &mut event.u.input2;
                    payload.size = copy_bytes_sized(data, &mut payload.data)? as u16;
                }
            }
            InputEvent::GetReportReply { err, data, .. } => {
                event.type_ = sys::uhid_event_type_UHID_GET_REPORT_REPLY as u32;
                unsafe {
                    let payload = &mut event.u.get_report_reply;
                    payload.err = err;
                    payload.size = copy_bytes_sized(data, &mut payload.data)? as u16;
                }
            }
            InputEvent::SetReportReply { err, .. } => {
                event.type_ = sys::uhid_event_type_UHID_SET_REPORT_REPLY as u32;
                unsafe {
                    let payload = &mut event.u.set_report_reply;
                    payload.err = err;
                }
            }
        };

        Ok(event)
    }
}

fn copy_bytes_sized(src: Vec<u8>, dst: &mut [u8]) -> Result<usize, StreamError> {
    let src_size = src.len();
    let dst_size = dst.len();

    if src_size > dst_size {
        return Err(StreamError::BufferOverflow(src_size, dst_size));
    }

    dst.get_mut(0..src_size)
        .unwrap()
        .copy_from_slice(src.as_slice());
    Ok(src_size)
}

fn copy_as_cstr(string: String, dst: &mut [u8]) -> Result<(), StreamError> {
    let mut src: Vec<u8> = ffi::CString::new(string)?.into_bytes_with_nul();
    let src_size = src.len();
    let dst_size = dst.len();

    if src_size >= dst_size {
        return Err(StreamError::BufferOverflow(src_size, dst_size));
    }

    src.extend(repeat(0).take(dst_size - src_size));
    dst.copy_from_slice(src.as_slice());
    Ok(())
}

fn decode_event(event: sys::uhid_event) -> Result<OutputEvent, StreamError> {
    if let Some(event_type) = to_uhid_event_type(event.type_) {
        match event_type {
            sys::uhid_event_type_UHID_START => Ok(unsafe {
                let payload = &event.u.start;
                OutputEvent::Start {
                    dev_flags: mem::transmute(payload.dev_flags),
                }
            }),
            sys::uhid_event_type_UHID_STOP => Ok(OutputEvent::Stop),
            sys::uhid_event_type_UHID_OPEN => Ok(OutputEvent::Open),
            sys::uhid_event_type_UHID_CLOSE => Ok(OutputEvent::Close),
            sys::uhid_event_type_UHID_OUTPUT => Ok(unsafe {
                let payload = &event.u.output;
                assert_eq!(
                    payload.rtype,
                    sys::uhid_report_type_UHID_OUTPUT_REPORT as u8
                );
                OutputEvent::Output {
                    data: slice::from_raw_parts(
                        &payload.data[0] as *const u8,
                        payload.size as usize,
                    ).to_vec(),
                }
            }),
            sys::uhid_event_type_UHID_GET_REPORT => Ok(unsafe {
                let payload = &event.u.get_report;
                OutputEvent::GetReport {
                    id: payload.id,
                    report_number: payload.rnum,
                    report_type: mem::transmute(payload.rtype),
                }
            }),
            sys::uhid_event_type_UHID_SET_REPORT => Ok(unsafe {
                let payload = &event.u.set_report;
                OutputEvent::SetReport {
                    id: payload.id,
                    report_number: payload.rnum,
                    report_type: mem::transmute(payload.rtype),
                    data: slice::from_raw_parts(
                        &payload.data[0] as *const u8,
                        payload.size as usize,
                    ).to_vec(),
                }
            }),
            _ => Err(StreamError::UnknownEventType(event.type_)),
        }
    } else {
        Err(StreamError::UnknownEventType(event.type_))
    }
}

fn to_uhid_event_type(value: u32) -> Option<sys::uhid_event_type> {
    let last_valid_value = sys::uhid_event_type_UHID_SET_REPORT_REPLY as u32;
    if value <= last_valid_value {
        Some(value)
    } else {
        None
    }
}

fn read_event(src: &mut BytesMut) -> Option<sys::uhid_event> {
    let uhid_event_size = mem::size_of::<sys::uhid_event>();
    if src.len() >= uhid_event_size {
        let bytes = src.split_to(uhid_event_size);
        let ptr = bytes.as_ptr();
        Some(unsafe { *(ptr as *const sys::uhid_event) })
    } else {
        None
    }
}

fn encode_event(event: &sys::uhid_event) -> &[u8] {
    unsafe { as_u8_slice(event) }
}

unsafe fn as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    slice::from_raw_parts((p as *const T) as *const u8, mem::size_of::<T>())
}

impl Decoder for Codec {
    type Item = OutputEvent;
    type Error = StreamError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Self::Item, Self::Error> {
        if let Some(event) = read_event(src) {
            Ok(decode_event(event)?)
        } else {
            Err(StreamError::Unknown)
        }
    }

    fn read_len(&self) -> usize {
        mem::size_of::<sys::uhid_event>()
    }
}

impl Encoder for Codec {
    type Item = InputEvent;
    type Error = StreamError;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let event = item.into_uhid_event()?;
        dst.extend_from_slice(encode_event(&event));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RDESC: [u8; 85] = [
        0x05, 0x01 /* USAGE_PAGE (Generic Desktop) */, 0x09, 0x02 /* USAGE (Mouse) */,
        0xa1, 0x01 /* COLLECTION (Application) */, 0x09, 0x01 /* USAGE (Pointer) */,
        0xa1, 0x00 /* COLLECTION (Physical) */, 0x85, 0x01 /* REPORT_ID (1) */, 0x05,
        0x09 /* USAGE_PAGE (Button) */, 0x19, 0x01 /* USAGE_MINIMUM (Button 1) */, 0x29,
        0x03 /* USAGE_MAXIMUM (Button 3) */, 0x15, 0x00 /* LOGICAL_MINIMUM (0) */, 0x25,
        0x01 /* LOGICAL_MAXIMUM (1) */, 0x95, 0x03 /* REPORT_COUNT (3) */, 0x75,
        0x01 /* REPORT_SIZE (1) */, 0x81, 0x02 /* INPUT (Data,Var,Abs) */, 0x95,
        0x01 /* REPORT_COUNT (1) */, 0x75, 0x05 /* REPORT_SIZE (5) */, 0x81,
        0x01 /* INPUT (Cnst,Var,Abs) */, 0x05, 0x01 /* USAGE_PAGE (Generic Desktop) */,
        0x09, 0x30 /* USAGE (X) */, 0x09, 0x31 /* USAGE (Y) */, 0x09,
        0x38 /* USAGE (WHEEL) */, 0x15, 0x81 /* LOGICAL_MINIMUM (-127) */, 0x25,
        0x7f /* LOGICAL_MAXIMUM (127) */, 0x75, 0x08 /* REPORT_SIZE (8) */, 0x95,
        0x03 /* REPORT_COUNT (3) */, 0x81, 0x06 /* INPUT (Data,Var,Rel) */,
        0xc0 /* END_COLLECTION */, 0xc0 /* END_COLLECTION */, 0x05,
        0x01 /* USAGE_PAGE (Generic Desktop) */, 0x09, 0x06 /* USAGE (Keyboard) */, 0xa1,
        0x01 /* COLLECTION (Application) */, 0x85, 0x02 /* REPORT_ID (2) */, 0x05,
        0x08 /* USAGE_PAGE (Led) */, 0x19, 0x01 /* USAGE_MINIMUM (1) */, 0x29,
        0x03 /* USAGE_MAXIMUM (3) */, 0x15, 0x00 /* LOGICAL_MINIMUM (0) */, 0x25,
        0x01 /* LOGICAL_MAXIMUM (1) */, 0x95, 0x03 /* REPORT_COUNT (3) */, 0x75,
        0x01 /* REPORT_SIZE (1) */, 0x91, 0x02 /* Output (Data,Var,Abs) */, 0x95,
        0x01 /* REPORT_COUNT (1) */, 0x75, 0x05 /* REPORT_SIZE (5) */, 0x91,
        0x01 /* Output (Cnst,Var,Abs) */, 0xc0 /* END_COLLECTION */,
    ];

    fn assert_bytes_eq(actual: &[u8], expected: &[u8]) {
        assert_eq!(actual.len(), expected.len(), "Size of slices differs");
        for index in 0..actual.len() {
            assert_eq!(
                actual[index],
                expected[index],
                "Bytes differ at index {}",
                index
            );
        }
    }

    #[test]
    fn encode_create_request() {
        let mut expected = vec![0; mem::size_of::<sys::uhid_event>()];
        expected[0] = 0x0b;
        expected[4] = 0x74;
        expected[5] = 0x65;
        expected[6] = 0x73;
        expected[7] = 0x74;
        expected[8] = 0x2d;
        expected[9] = 0x75;
        expected[10] = 0x68;
        expected[11] = 0x69;
        expected[12] = 0x64;
        expected[13] = 0x2d;
        expected[14] = 0x64;
        expected[15] = 0x65;
        expected[16] = 0x76;
        expected[17] = 0x69;
        expected[18] = 0x63;
        expected[19] = 0x65;
        expected[260] = 0x55;
        expected[262] = 0x03;
        expected[264] = 0xd9;
        expected[265] = 0x15;
        expected[268] = 0x37;
        expected[269] = 0x0a;
        expected[280] = 0x05;
        expected[281] = 0x01;
        expected[282] = 0x09;
        expected[283] = 0x02;
        expected[284] = 0xa1;
        expected[285] = 0x01;
        expected[286] = 0x09;
        expected[287] = 0x01;
        expected[288] = 0xa1;
        expected[290] = 0x85;
        expected[291] = 0x01;
        expected[292] = 0x05;
        expected[293] = 0x09;
        expected[294] = 0x19;
        expected[295] = 0x01;
        expected[296] = 0x29;
        expected[297] = 0x03;
        expected[298] = 0x15;
        expected[300] = 0x25;
        expected[301] = 0x01;
        expected[302] = 0x95;
        expected[303] = 0x03;
        expected[304] = 0x75;
        expected[305] = 0x01;
        expected[306] = 0x81;
        expected[307] = 0x02;
        expected[308] = 0x95;
        expected[309] = 0x01;
        expected[310] = 0x75;
        expected[311] = 0x05;
        expected[312] = 0x81;
        expected[313] = 0x01;
        expected[314] = 0x05;
        expected[315] = 0x01;
        expected[316] = 0x09;
        expected[317] = 0x30;
        expected[318] = 0x09;
        expected[319] = 0x31;
        expected[320] = 0x09;
        expected[321] = 0x38;
        expected[322] = 0x15;
        expected[323] = 0x81;
        expected[324] = 0x25;
        expected[325] = 0x7f;
        expected[326] = 0x75;
        expected[327] = 0x08;
        expected[328] = 0x95;
        expected[329] = 0x03;
        expected[330] = 0x81;
        expected[331] = 0x06;
        expected[332] = 0xc0;
        expected[333] = 0xc0;
        expected[334] = 0x05;
        expected[335] = 0x01;
        expected[336] = 0x09;
        expected[337] = 0x06;
        expected[338] = 0xa1;
        expected[339] = 0x01;
        expected[340] = 0x85;
        expected[341] = 0x02;
        expected[342] = 0x05;
        expected[343] = 0x08;
        expected[344] = 0x19;
        expected[345] = 0x01;
        expected[346] = 0x29;
        expected[347] = 0x03;
        expected[348] = 0x15;
        expected[350] = 0x25;
        expected[351] = 0x01;
        expected[352] = 0x95;
        expected[353] = 0x03;
        expected[354] = 0x75;
        expected[355] = 0x01;
        expected[356] = 0x91;
        expected[357] = 0x02;
        expected[358] = 0x95;
        expected[359] = 0x01;
        expected[360] = 0x75;
        expected[361] = 0x05;
        expected[362] = 0x91;
        expected[363] = 0x01;
        expected[364] = 0xc0;
        let mut result = BytesMut::new();

        Codec
            .encode(
                InputEvent::Create {
                    name: String::from("test-uhid-device"),
                    phys: String::from(""),
                    uniq: String::from(""),
                    bus: Bus::USB,
                    vendor: 0x15d9,
                    product: 0x0a37,
                    version: 0,
                    country: 0,
                    data: RDESC.to_vec(),
                },
                &mut result,
            )
            .unwrap();

        assert_bytes_eq(&result[..], &expected);
    }

    #[test]
    fn encode_destroy_request() {
        let mut expected = vec![0; mem::size_of::<sys::uhid_event>()];
        expected[0] = 0x01;
        let mut result = BytesMut::new();

        Codec.encode(InputEvent::Destroy, &mut result).unwrap();

        assert_bytes_eq(&result[..], &expected);
    }
}
