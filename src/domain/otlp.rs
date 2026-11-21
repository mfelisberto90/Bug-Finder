use crate::domain::models::{LogLevel, NormalizedLog, now_ms};
use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtlpDecodeError(pub String);

impl std::fmt::Display for OtlpDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub fn decode_otlp_logs(body: &[u8], content_type: &str) -> Result<Vec<NormalizedLog>, OtlpDecodeError> {
    if content_type.to_ascii_lowercase().contains("json") {
        decode_otlp_json(body)
    } else {
        decode_otlp_protobuf(body)
    }
}

fn should_skip_resource_attr(key: &str) -> bool {
    key.starts_with("telemetry.sdk.") || key.starts_with("telemetry.auto.")
}

fn unwrap_otel_json_anyvalue(val: &Value) -> Value {
    let Some(obj) = val.as_object() else {
        return val.clone();
    };
    if let Some(s) = obj.get("stringValue").or_else(|| obj.get("string_value")) {
        return s.clone();
    }
    if let Some(i) = obj.get("intValue").or_else(|| obj.get("int_value")) {
        if let Some(s) = i.as_str() {
            if let Ok(parsed) = s.parse::<i64>() {
                return Value::Number(parsed.into());
            }
        }
        return i.clone();
    }
    if let Some(d) = obj.get("doubleValue").or_else(|| obj.get("double_value")) {
        return d.clone();
    }
    if let Some(b) = obj.get("boolValue").or_else(|| obj.get("bool_value")) {
        return b.clone();
    }
    if let Some(bytes) = obj.get("bytesValue").or_else(|| obj.get("bytes_value")) {
        return bytes.clone();
    }
    if let Some(arr) = obj.get("arrayValue").or_else(|| obj.get("array_value")) {
        if let Some(vals) = arr.get("values").and_then(|v| v.as_array()) {
            return Value::Array(vals.iter().map(unwrap_otel_json_anyvalue).collect());
        }
    }
    if let Some(kv) = obj.get("kvlistValue").or_else(|| obj.get("kvlist_value")) {
        if let Some(vals) = kv.get("values").and_then(|v| v.as_array()) {
            let mut m = Map::new();
            for item in vals {
                if let Some(k) = item.get("key").and_then(|v| v.as_str()) {
                    let vv = item
                        .get("value")
                        .map(unwrap_otel_json_anyvalue)
                        .unwrap_or(Value::Null);
                    m.insert(k.to_string(), vv);
                }
            }
            return Value::Object(m);
        }
    }
    val.clone()
}

fn parse_nano_to_ms(v: Option<&Value>) -> Option<i64> {
    let val = v?;
    let nanos: u64 = if let Some(n) = val.as_u64() {
        n
    } else if let Some(s) = val.as_str() {
        s.parse::<u64>().ok()?
    } else {
        return None;
    };
    if nanos == 0 {
        None
    } else {
        Some((nanos / 1_000_000) as i64)
    }
}

fn is_all_zero_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b == b'0')
}

fn decode_otlp_json(body: &[u8]) -> Result<Vec<NormalizedLog>, OtlpDecodeError> {
    let root: Value =
        serde_json::from_slice(body).map_err(|e| OtlpDecodeError(format!("Invalid OTLP JSON: {e}")))?;
    let rls = root
        .get("resourceLogs")
        .or_else(|| root.get("resource_logs"))
        .and_then(|v| v.as_array())
        .ok_or_else(|| OtlpDecodeError("Missing resourceLogs".into()))?;

    let mut out = Vec::new();
    for rl in rls {
        let mut res_attrs = Vec::new();
        if let Some(attrs) = rl
            .get("resource")
            .and_then(|r| r.get("attributes"))
            .and_then(|a| a.as_array())
        {
            for attr in attrs {
                if let Some(k) = attr.get("key").and_then(|v| v.as_str()) {
                    if !should_skip_resource_attr(k) {
                        let v = attr
                            .get("value")
                            .map(unwrap_otel_json_anyvalue)
                            .unwrap_or(Value::Null);
                        res_attrs.push((k.to_string(), v));
                    }
                }
            }
        }

        let scope_logs = rl
            .get("scopeLogs")
            .or_else(|| rl.get("scope_logs"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        for sl in scope_logs {
            let recs = sl
                .get("logRecords")
                .or_else(|| sl.get("log_records"))
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            for rec in recs {
                let ts_ms = parse_nano_to_ms(rec.get("timeUnixNano").or_else(|| rec.get("time_unix_nano")))
                    .or_else(|| {
                        parse_nano_to_ms(
                            rec.get("observedTimeUnixNano")
                                .or_else(|| rec.get("observed_time_unix_nano")),
                        )
                    })
                    .unwrap_or_else(now_ms);

                let sev_num = rec
                    .get("severityNumber")
                    .or_else(|| rec.get("severity_number"))
                    .and_then(|v| v.as_u64())
                    .filter(|&n| n > 0)
                    .map(|n| n as u16);

                let sev_text = rec
                    .get("severityText")
                    .or_else(|| rec.get("severity_text"))
                    .and_then(|v| v.as_str());

                let level = sev_text
                    .map(LogLevel::from_str_loose)
                    .or_else(|| sev_num.map(LogLevel::from_otel_severity))
                    .unwrap_or(LogLevel::Info);

                let body_str = match rec.get("body") {
                    Some(b) => match unwrap_otel_json_anyvalue(b) {
                        Value::String(s) => s,
                        Value::Null => String::new(),
                        other => other.to_string(),
                    },
                    None => String::new(),
                };

                let trace_id = rec
                    .get("traceId")
                    .or_else(|| rec.get("trace_id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty() && !is_all_zero_hex(s));

                let span_id = rec
                    .get("spanId")
                    .or_else(|| rec.get("span_id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty() && !is_all_zero_hex(s));

                let mut attrs_map = Map::new();
                for (k, v) in &res_attrs {
                    attrs_map.insert(k.clone(), v.clone());
                }
                if let Some(rec_attrs) = rec.get("attributes").and_then(|v| v.as_array()) {
                    for attr in rec_attrs {
                        if let Some(k) = attr.get("key").and_then(|v| v.as_str()) {
                            let v = attr
                                .get("value")
                                .map(unwrap_otel_json_anyvalue)
                                .unwrap_or(Value::Null);
                            attrs_map.insert(k.to_string(), v);
                        }
                    }
                }

                let (service, environment, host) = extract_resource_meta(&attrs_map);
                out.push(NormalizedLog {
                    timestamp_ms: ts_ms,
                    level,
                    severity_number: sev_num,
                    body: body_str,
                    service,
                    environment,
                    host,
                    trace_id,
                    span_id,
                    attributes: Value::Object(attrs_map),
                });
            }
        }
    }

    Ok(out)
}

fn extract_resource_meta(attrs: &Map<String, Value>) -> (String, String, String) {
    let service = attrs
        .get("service.name")
        .or_else(|| attrs.get("service"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let environment = attrs
        .get("deployment.environment")
        .or_else(|| attrs.get("deployment.environment.name"))
        .or_else(|| attrs.get("environment"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let host = attrs
        .get("host.name")
        .or_else(|| attrs.get("host"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    (service, environment, host)
}

// ============================================================================
// Pure-Rust OTLP Protobuf Wire Decoder (zero protoc / zero C++ build deps)
// ============================================================================

struct PbCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> PbCursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn eof(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn read_varint(&mut self) -> Result<u64, OtlpDecodeError> {
        let mut val = 0u64;
        let mut shift = 0u32;
        while self.pos < self.buf.len() && shift < 64 {
            let b = self.buf[self.pos];
            self.pos += 1;
            val |= ((b & 0x7F) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(val);
            }
            shift += 7;
        }
        Err(OtlpDecodeError("Truncated or malformed varint".into()))
    }

    fn read_fixed64(&mut self) -> Result<u64, OtlpDecodeError> {
        if self.pos + 8 > self.buf.len() {
            return Err(OtlpDecodeError("Truncated fixed64".into()));
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_le_bytes(arr))
    }

    fn read_fixed32(&mut self) -> Result<u32, OtlpDecodeError> {
        if self.pos + 4 > self.buf.len() {
            return Err(OtlpDecodeError("Truncated fixed32".into()));
        }
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&self.buf[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(u32::from_le_bytes(arr))
    }

    fn read_bytes(&mut self) -> Result<&'a [u8], OtlpDecodeError> {
        let len = self.read_varint()? as usize;
        if self.pos + len > self.buf.len() {
            return Err(OtlpDecodeError("Truncated length-delimited field".into()));
        }
        let slice = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    fn skip_field(&mut self, wire_type: u64) -> Result<(), OtlpDecodeError> {
        match wire_type {
            0 => {
                let _ = self.read_varint()?;
            }
            1 => {
                let _ = self.read_fixed64()?;
            }
            2 => {
                let _ = self.read_bytes()?;
            }
            5 => {
                let _ = self.read_fixed32()?;
            }
            _ => return Err(OtlpDecodeError(format!("Unsupported wire type {wire_type}"))),
        }
        Ok(())
    }

    fn read_tag(&mut self) -> Result<(u64, u64), OtlpDecodeError> {
        let tag = self.read_varint()?;
        Ok((tag >> 3, tag & 0x07))
    }
}

fn decode_otlp_protobuf(body: &[u8]) -> Result<Vec<NormalizedLog>, OtlpDecodeError> {
    let mut cur = PbCursor::new(body);
    let mut out = Vec::new();
    while !cur.eof() {
        let (field, wt) = cur.read_tag()?;
        if field == 1 && wt == 2 {
            let rl_bytes = cur.read_bytes()?;
            decode_pb_resource_logs(rl_bytes, &mut out)?;
        } else {
            cur.skip_field(wt)?;
        }
    }
    Ok(out)
}

fn decode_pb_resource_logs(buf: &[u8], out: &mut Vec<NormalizedLog>) -> Result<(), OtlpDecodeError> {
    let mut cur = PbCursor::new(buf);
    let mut res_attrs: Vec<(String, Value)> = Vec::new();
    let mut scope_slices: Vec<&[u8]> = Vec::new();

    while !cur.eof() {
        let (field, wt) = cur.read_tag()?;
        match (field, wt) {
            (1, 2) => {
                let res_bytes = cur.read_bytes()?;
                res_attrs = decode_pb_resource(res_bytes)?;
            }
            (2, 2) => {
                scope_slices.push(cur.read_bytes()?);
            }
            _ => cur.skip_field(wt)?,
        }
    }

    for sl_bytes in scope_slices {
        decode_pb_scope_logs(sl_bytes, &res_attrs, out)?;
    }
    Ok(())
}

fn decode_pb_resource(buf: &[u8]) -> Result<Vec<(String, Value)>, OtlpDecodeError> {
    let mut cur = PbCursor::new(buf);
    let mut attrs = Vec::new();
    while !cur.eof() {
        let (field, wt) = cur.read_tag()?;
        if field == 1 && wt == 2 {
            let kv = decode_pb_key_value(cur.read_bytes()?)?;
            if !should_skip_resource_attr(&kv.0) {
                attrs.push(kv);
            }
        } else {
            cur.skip_field(wt)?;
        }
    }
    Ok(attrs)
}

fn decode_pb_scope_logs(
    buf: &[u8],
    res_attrs: &[(String, Value)],
    out: &mut Vec<NormalizedLog>,
) -> Result<(), OtlpDecodeError> {
    let mut cur = PbCursor::new(buf);
    while !cur.eof() {
        let (field, wt) = cur.read_tag()?;
        if field == 2 && wt == 2 {
            let rec_bytes = cur.read_bytes()?;
            out.push(decode_pb_log_record(rec_bytes, res_attrs)?);
        } else {
            cur.skip_field(wt)?;
        }
    }
    Ok(())
}

fn decode_pb_log_record(
    buf: &[u8],
    res_attrs: &[(String, Value)],
) -> Result<NormalizedLog, OtlpDecodeError> {
    let mut cur = PbCursor::new(buf);
    let mut time_nano: u64 = 0;
    let mut observed_nano: u64 = 0;
    let mut severity_num: Option<u16> = None;
    let mut severity_text: Option<String> = None;
    let mut body = String::new();
    let mut trace_id: Option<String> = None;
    let mut span_id: Option<String> = None;
    let mut attrs_map = Map::new();

    for (k, v) in res_attrs {
        attrs_map.insert(k.clone(), v.clone());
    }

    while !cur.eof() {
        let (field, wt) = cur.read_tag()?;
        match (field, wt) {
            (1, 1) => time_nano = cur.read_fixed64()?,
            (11, 1) => observed_nano = cur.read_fixed64()?,
            (2, 0) => {
                let s = cur.read_varint()? as u16;
                if s > 0 {
                    severity_num = Some(s);
                }
            }
            (3, 2) => {
                let s = String::from_utf8_lossy(cur.read_bytes()?).to_string();
                if !s.is_empty() {
                    severity_text = Some(s);
                }
            }
            (5, 2) => {
                let val = decode_pb_anyvalue(cur.read_bytes()?, 0)?;
                body = match val {
                    Value::String(s) => s,
                    Value::Null => String::new(),
                    other => other.to_string(),
                };
            }
            (6, 2) => {
                let (k, v) = decode_pb_key_value(cur.read_bytes()?)?;
                attrs_map.insert(k, v);
            }
            (9, 2) => {
                let bytes = cur.read_bytes()?;
                if !bytes.is_empty() && bytes.iter().any(|&b| b != 0) {
                    trace_id = Some(hex::encode(bytes));
                }
            }
            (10, 2) => {
                let bytes = cur.read_bytes()?;
                if !bytes.is_empty() && bytes.iter().any(|&b| b != 0) {
                    span_id = Some(hex::encode(bytes));
                }
            }
            _ => cur.skip_field(wt)?,
        }
    }

    let eff_nano = if time_nano > 0 { time_nano } else { observed_nano };
    let ts_ms = if eff_nano > 0 {
        (eff_nano / 1_000_000) as i64
    } else {
        now_ms()
    };

    let level = severity_text
        .as_deref()
        .map(LogLevel::from_str_loose)
        .or_else(|| severity_num.map(LogLevel::from_otel_severity))
        .unwrap_or(LogLevel::Info);

    let (service, environment, host) = extract_resource_meta(&attrs_map);

    Ok(NormalizedLog {
        timestamp_ms: ts_ms,
        level,
        severity_number: severity_num,
        body,
        service,
        environment,
        host,
        trace_id,
        span_id,
        attributes: Value::Object(attrs_map),
    })
}

fn decode_pb_key_value(buf: &[u8]) -> Result<(String, Value), OtlpDecodeError> {
    let mut cur = PbCursor::new(buf);
    let mut key = String::new();
    let mut val = Value::Null;
    while !cur.eof() {
        let (field, wt) = cur.read_tag()?;
        match (field, wt) {
            (1, 2) => key = String::from_utf8_lossy(cur.read_bytes()?).to_string(),
            (2, 2) => val = decode_pb_anyvalue(cur.read_bytes()?, 0)?,
            _ => cur.skip_field(wt)?,
        }
    }
    Ok((key, val))
}

fn decode_pb_anyvalue(buf: &[u8], depth: usize) -> Result<Value, OtlpDecodeError> {
    if depth > 16 {
        return Ok(Value::String("[MaxDepth]".into()));
    }
    let mut cur = PbCursor::new(buf);
    let mut out = Value::Null;
    while !cur.eof() {
        let (field, wt) = cur.read_tag()?;
        match (field, wt) {
            (1, 2) => out = Value::String(String::from_utf8_lossy(cur.read_bytes()?).to_string()),
            (2, 0) => out = Value::Bool(cur.read_varint()? != 0),
            (3, 0) => out = Value::Number((cur.read_varint()? as i64).into()),
            (4, 1) => {
                let bits = cur.read_fixed64()?;
                let f = f64::from_bits(bits);
                out = serde_json::Number::from_f64(f)
                    .map(Value::Number)
                    .unwrap_or(Value::Null);
            }
            (5, 2) => {
                let arr_bytes = cur.read_bytes()?;
                let mut ac = PbCursor::new(arr_bytes);
                let mut vec = Vec::new();
                while !ac.eof() {
                    let (af, awt) = ac.read_tag()?;
                    if af == 1 && awt == 2 {
                        vec.push(decode_pb_anyvalue(ac.read_bytes()?, depth + 1)?);
                    } else {
                        ac.skip_field(awt)?;
                    }
                }
                out = Value::Array(vec);
            }
            (6, 2) => {
                let kv_bytes = cur.read_bytes()?;
                let mut kc = PbCursor::new(kv_bytes);
                let mut map = Map::new();
                while !kc.eof() {
                    let (kf, kwt) = kc.read_tag()?;
                    if kf == 1 && kwt == 2 {
                        let (k, v) = decode_pb_key_value(kc.read_bytes()?)?;
                        map.insert(k, v);
                    } else {
                        kc.skip_field(kwt)?;
                    }
                }
                out = Value::Object(map);
            }
            (7, 2) => out = Value::String(hex::encode(cur.read_bytes()?)),
            _ => cur.skip_field(wt)?,
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_varint(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let b = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                break;
            } else {
                out.push(b | 0x80);
            }
        }
    }

    fn pb_bytes(field: u64, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        push_varint(&mut out, (field << 3) | 2);
        push_varint(&mut out, data.len() as u64);
        out.extend_from_slice(data);
        out
    }

    fn pb_varint(field: u64, val: u64) -> Vec<u8> {
        let mut out = Vec::new();
        push_varint(&mut out, field << 3);
        push_varint(&mut out, val);
        out
    }

    fn pb_fixed64(field: u64, val: u64) -> Vec<u8> {
        let mut out = Vec::new();
        push_varint(&mut out, (field << 3) | 1);
        out.extend_from_slice(&val.to_le_bytes());
        out
    }

    #[test]
    fn decodes_otlp_json_and_skips_sdk_attrs() {
        let payload = br#"{
          "resourceLogs": [{
            "resource": {
              "attributes": [
                {"key":"service.name","value":{"stringValue":"checkout-api"}},
                {"key":"deployment.environment","value":{"stringValue":"production"}},
                {"key":"telemetry.sdk.name","value":{"stringValue":"opentelemetry"}}
              ]
            },
            "scopeLogs": [{
              "logRecords": [{
                "timeUnixNano": "1700000000000000000",
                "severityNumber": 17,
                "severityText": "ERROR",
                "body": {"stringValue": "Payment gateway timeout"},
                "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
                "spanId": "00f067aa0ba902b7",
                "attributes": [{"key":"order_id","value":{"intValue":"42"}}]
              }]
            }]
          }]
        }"#;
        let logs = decode_otlp_logs(payload, "application/json").unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].service, "checkout-api");
        assert_eq!(logs[0].environment, "production");
        assert_eq!(logs[0].level, LogLevel::Error);
        assert_eq!(logs[0].body, "Payment gateway timeout");
        assert_eq!(logs[0].attributes["order_id"], 42);
        assert!(logs[0].attributes.get("telemetry.sdk.name").is_none());
    }

    #[test]
    fn decodes_otlp_binary_protobuf() {
        let any_svc = pb_bytes(1, b"worker-rs");
        let kv_svc = [pb_bytes(1, b"service.name"), pb_bytes(2, &any_svc)].concat();
        let resource = pb_bytes(1, &kv_svc);

        let any_body = pb_bytes(1, b"Queue drained");
        let mut log_rec = Vec::new();
        log_rec.extend(pb_fixed64(1, 1_700_000_005_000_000_000));
        log_rec.extend(pb_varint(2, 13)); // WARN
        log_rec.extend(pb_bytes(3, b"WARN"));
        log_rec.extend(pb_bytes(5, &any_body));
        log_rec.extend(pb_bytes(9, &[0xaa; 16]));
        log_rec.extend(pb_bytes(10, &[0xbb; 8]));

        let scope_logs = pb_bytes(2, &log_rec);
        let mut resource_logs = pb_bytes(1, &resource);
        resource_logs.extend(pb_bytes(2, &scope_logs));
        let req = pb_bytes(1, &resource_logs);

        let logs = decode_otlp_logs(&req, "application/x-protobuf").unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].service, "worker-rs");
        assert_eq!(logs[0].level, LogLevel::Warn);
        assert_eq!(logs[0].body, "Queue drained");
        assert_eq!(logs[0].trace_id.as_deref(), Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert_eq!(logs[0].span_id.as_deref(), Some("bbbbbbbbbbbbbbbb"));
    }
}
