# NĐ13/2023 Compliance Checklist — MedViet AI Platform

**Thực hiện bởi:** Đinh Thái Tuấn — MSSV: 2A202600360

---

## A. Data Localization

- [x] Tất cả patient data lưu trên servers đặt tại Việt Nam
- [x] Backup cũng phải ở trong lãnh thổ VN
- [x] Log việc transfer data ra ngoài nếu có

## B. Explicit Consent

- [x] Thu thập consent trước khi dùng data cho AI training
- [x] Có mechanism để user rút consent (Right to Erasure)
- [x] Lưu consent record với timestamp

## C. Breach Notification (72h)

- [x] Có incident response plan
- [x] Alert tự động khi phát hiện breach
- [x] Quy trình báo cáo đến cơ quan có thẩm quyền trong 72h

## D. DPO Appointment

- [x] Đã bổ nhiệm Data Protection Officer
- [x] DPO có thể liên hệ tại: dpo@medviet.vn

## E. Technical Controls (mapping từ NĐ13/2023)

| NĐ13 Requirement      | Technical Control                           | Status         | Owner          |
|-----------------------|---------------------------------------------|----------------|----------------|
| Data minimization     | PII anonymization pipeline (Presidio)       | ✅ Done         | AI Team        |
| Access control        | RBAC (Casbin) + ABAC (OPA)                  | ✅ Done         | Platform Team  |
| Encryption            | AES-256-GCM at rest, TLS 1.3 in transit     | ✅ Done         | Infra Team     |
| Audit logging         | FastAPI middleware + ELK Stack              | ✅ Done         | Platform Team  |
| Breach detection      | Prometheus anomaly alerts + Grafana         | ✅ Done         | Security Team  |

## F. Technical Solutions cho các mục còn thiếu

### Audit Logging

**Giải pháp:** Triển khai FastAPI middleware ghi lại mọi API request vào ELK Stack
(Elasticsearch + Logstash + Kibana). Mỗi log entry gồm: `timestamp`, `user_id`,
`role`, `method`, `path`, `status_code`, `client_ip`. Retention 90 ngày, chỉ admin
được truy cập.

```python
@app.middleware("http")
async def audit_log_middleware(request: Request, call_next):
    response = await call_next(request)
    logger.info({
        "timestamp": datetime.utcnow().isoformat(),
        "method": request.method,
        "path": request.url.path,
        "status_code": response.status_code,
        "client_ip": request.client.host,
    })
    return response
```

### Breach Detection

**Giải pháp:** Dùng Prometheus custom metrics và Grafana alert rules:

1. `api_unauthorized_attempts_total` — đếm số request bị 401/403 theo user.
2. `data_export_records_total` — theo dõi số bản ghi xuất ra mỗi phút.
3. Alert rule: nếu `api_unauthorized_attempts_total` tăng > 20 lần/phút
   → gửi PagerDuty notification → DPO xác nhận → nếu là breach thật,
   báo cáo cơ quan Bảo vệ dữ liệu cá nhân trong vòng **72 giờ** theo NĐ13/2023 Điều 23.
