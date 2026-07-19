# Secure Payment Architecture & STRIDE Threat Model

A security architecture and threat-modelling project for a multi-tenant online payment-processing platform.

The project applies the STRIDE framework to identify threats across authentication, authorization, data storage, API communication, monitoring, and administrative access. It then proposes defence-in-depth controls, risk-treatment decisions, and residual-risk considerations.

---
## Executive Summary

This project develops a defence-in-depth architecture and STRIDE threat model for a hypothetical multi-tenant payment-processing platform.

The assessment identifies critical assets, maps trust boundaries, analyzes threats across authentication, authorization, storage, APIs, monitoring and administrative access, and proposes preventive, detective and corrective controls.

The design emphasizes:

- strong identity and service authentication,
- least-privilege authorization,
- payment-data tokenization,
- network segmentation,
- cryptographically verified webhooks,
- immutable audit logging,
- privileged-access management,
- secure deployment and monitoring.

> **Scope note:** This is an academic architecture and threat-modelling exercise for a hypothetical payment platform. It is not a certification of PCI DSS compliance and has not undergone production validation, penetration testing or formal regulatory review.
---

## Project Scope

- Layered payment-platform architecture
- Asset identification and data classification
- Trust-boundary analysis
- STRIDE threat modelling
- Identity and access management
- Network segmentation and data protection
- Logging, monitoring, and secure deployment
- Risk treatment and residual-risk analysis

**Author:** Bilal Ahmed  
**Course:** Cybersecurity: Theory and Tools  
**Completed:** March 2026


---

# 1. System Definition and Architecture

## 1.1 System Overview

This report documents the secure architecture and STRIDE-based threat model for an Online Payment Processing Application — a multi-tenant platform enabling customers to pay merchants, process refunds, handle payment disputes, and reconcile settlements with banking partners. The system is designed around a layered, cloud-compatible architecture and integrates with an external payment processor and a core banking system.

The platform operates in a high-sensitivity domain, handling payment card data, financial transaction records, and personally identifiable information. Its security posture is built on four foundational principles:

- **Confidentiality** — all sensitive financial and personal data is protected from unauthorized disclosure at rest and in transit.
- **Integrity** — transaction processing, settlement records, and audit trails are protected against unauthorized modification.
- **Availability** — payment operations must remain continuously accessible; service disruptions carry direct financial and reputational consequences.
- **Accountability** — all system actions, particularly administrative and financial operations, must be attributable to a specific authenticated identity.

The threat model considers both external adversaries targeting public-facing infrastructure and insider threats arising from the misuse of legitimate administrative access.

## 1.2 Application Components

The application is structured across three layers: a frontend presentation layer, a backend services layer, and a private data storage zone.

**Frontend Portals**

- Customer Web Application — checkout, payment status tracking, and order history.
- Merchant Portal — transaction visibility, refund initiation, and settlement reporting.
- Admin Portal — refund approvals, dispute management, and operational monitoring dashboards. Accessible only over VPN.

All frontend portals communicate exclusively with backend services over HTTPS/TLS.

**Backend Services**

- API Gateway — the single external entry point, responsible for authentication enforcement, authorization, rate limiting, request validation, and routing.
- API Backend — core business logic including order management and payment validation rules.
- Payment Service — payment orchestration, tokenization, and communication with the external Payment Processor API.
- Webhook Handler — receives and validates inbound payment confirmation callbacks from the payment processor; updates transaction state upon successful verification.
- Admin Service — processes refund approvals, dispute resolutions, and financial adjustments initiated through the Admin Portal.

**Data Storage (Private Zone)**

- User Database — customer account data and hashed credentials.
- Merchant Database — merchant profiles and API credentials.
- Transaction/Billing Database — orders, payment records, refunds, and settlement details.
- Audit Log Store — append-only, immutable records of security events and administrative actions.

**External Integrations**

- Payment Processor API — handles authorization, capture, tokenization, and payment confirmation callbacks.
- Core Banking System — settlement and reconciliation processing.
- Notification Service — email and SMS delivery for payment alerts and confirmations.

## 1.3 Users and Roles

| **Role** | **Description** |
|---|---|
| Customer | Initiates payments and views order history through the Customer Web Application. |
| Merchant | Views transaction records and submits refund requests via the Merchant Portal. |
| Application Admin | Manages operational tasks — refund approvals, dispute resolution — through the Admin Portal and Admin Service. |
| System Administrator | Manages infrastructure, CI/CD pipeline, deployment approvals, and core security services. |
| External Attacker | Internet-based adversary targeting public-facing components through automated or targeted attacks. |
| Insider Threat | Malicious or compromised internal user with legitimate access who abuses their privileges. |

Administrative roles — Application Admin and System Administrator — carry elevated access and require additional controls including MFA, VPN access, and session recording.

## 1.4 Data Types Handled

- Payment Card Data — card number and expiry are handled only within the minimum required payment flow; CVV is used only for authorization and is never retained after authorization.
- Payment Tokens — tokenized card representations (Highly Sensitive)
- Customer Personal Data — name, email, billing address (Sensitive)
- Merchant Credentials — API keys and authentication tokens (Highly Sensitive)
- Transaction Records — orders, payments, refunds (Sensitive)
- JWT / Session Tokens — active session identifiers (Sensitive)
- Audit Logs — administrative and security event records (Moderate to Sensitive)

## 1.5 Trust Boundaries

The architecture enforces six trust boundaries that separate zones of differing trust levels. Data crossing any boundary is subject to authentication, validation, and encryption controls.

| **Boundary** | **Zone Separation** | **Description** | **Security Rationale** |
|---|---|---|---|
| TB1 | Internet ↔ API Gateway | Separates untrusted public internet traffic from internal production services. All external requests enter through the API Gateway. | Prevents direct access to backend systems and enforces authentication and input validation at the system perimeter. |
| TB2 | Frontend ↔ Backend Services | Customer, Merchant, and Admin portals communicate exclusively through the API Gateway — never directly with backend services. | Maintains separation between presentation and business logic layers; prevents direct database access from the front end. |
| TB3 | Admin Portal ↔ Admin Service | Administrative functions operate through a dedicated, isolated service layer accessible only via VPN. | Administrators hold elevated privileges with direct financial impact; isolation limits blast radius of a compromised admin session. |
| TB4 | Backend Services ↔ Data Storage | All databases reside in a restricted private zone accessible only to authorized backend services. | Protects credentials, tokens, and transaction records from unauthorized direct access, even from within the internal network. |
| TB5 | Production Zone ↔ External Systems | Communication between internal services and external providers crosses organizational boundaries. | External systems are untrusted; integration risk is managed through mTLS and strict API validation. |
| TB6 | Payment Processor ↔ Webhook Handler | The Webhook Handler receives inbound payment confirmation callbacks — a secondary external entry point. | Inbound webhook data must be cryptographically verified before any transaction state is updated. |

## 1.6 High-Level Architecture

The logical architecture follows a layered, defense-in-depth model:

![Task 1 Architecture](task1.png)

---

# 2. Asset Identification and Security Objectives

## 2.1 Asset Inventory

The following table identifies all critical assets in the system, their location, sensitivity classification, and the applicable CIAA security objectives.

| **ID** | **Asset Name** | **Category** | **Description** | **Location** | **Sensitivity** | **CIAA** |
|---|---|---|---|---|---|---|
| A1 | User Credentials | Credentials | Customer login data — username and hashed password | User Database | High | C, I, A, Ac |
| A2 | Merchant API Credentials | Credentials | API keys and authentication tokens used by merchant integrations | Merchant Database | High | C, I, A, Ac |
| A3 | Admin Credentials | Credentials | Administrative login credentials and active session tokens | User Database | High | C, I, A, Ac |
| A4 | Payment Card Data | Financial | Card data processed transiently by the Payment Service and tokenized through the payment processor; CVV is never stored | Payment Service / External Payment Processor | Critical | C, I, A, Ac |
| A5 | Payment Tokens | Financial | Tokenized representation of card data used in place of raw card numbers | Payment Service | High | C, I, A |
| A6 | Transaction Records | Financial | Orders, payments, refunds, and settlement data | Transaction/Billing DB | High | C, I, A, Ac |
| A7 | Customer Personal Data | Personal | Name, email, phone number, billing address | User Database | Medium | C, I, A |
| A8 | Merchant Profile Data | Business | Merchant details and settlement preferences | Merchant Database | Medium | C, I, A |
| A9 | Business Logic | Application | Payment validation, refund rules, and settlement workflows | API Backend / Admin Service | High | I, A |
| A10 | Audit Logs | Logging | Immutable records of administrative actions and security events | Audit Log Store | High | I, A, Ac |
| A11 | JWT / Session Tokens | Auth Data | Session identifiers used for user authentication across all portals | API Gateway | High | C, I, A |
| A12 | Payment Processor Contract | Integration | API communication interface with the external payment processor | Payment Service | High | I, A |

## 2.2 Security Objective Definitions

- **Confidentiality (C):** Asset must not be disclosed to unauthorized parties. Applies especially to card data, credentials, and session tokens.
- **Integrity (I):** Asset must not be altered without authorization. Applies to transaction records, audit logs, and business logic.
- **Availability (A):** Asset must be accessible when required. Applies to the payment pipeline, API Gateway, and all active databases.
- **Accountability (Ac):** All access and modification must be attributable to a specific authenticated identity. Critical for financial and administrative operations and regulatory compliance.

---

# 3. Threat Modeling (STRIDE)

## 3.1 Methodology

This threat model applies the STRIDE framework — Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege — systematically across all six required threat areas: Authentication, Authorization, Data Storage, API Communication, Logging and Monitoring, and Administrative Access.

Each threat is documented with its affected component, a description of the attack vector, its potential impact, a qualitative risk level, the reasoning behind that risk rating, and the primary mitigation control assigned. The STRIDE model was chosen for its component-centric approach, which maps naturally onto the system's layered architecture and makes it straightforward to assign control ownership to specific services.

## 3.2 Threat Diagram — Annotated Architecture

The following annotated architecture diagram maps each threat to its affected component and location in the system. Threat IDs reference the Threat Model Table in Section 3.3.

![Task 3 Threat Diagram](ThreatModel.png)

### Risk-Rating Method

Risks are rated qualitatively using likelihood and impact:

| Rating | Interpretation |
|---|---|
| High | Realistic attack path with major financial, regulatory, operational or confidentiality impact |
| Medium | Plausible attack with meaningful but contained impact, or requiring elevated access |
| Low | Limited likelihood or impact under the stated architecture and assumptions |

The ratings represent inherent risk before the listed primary controls. Residual risk should be reassessed after implementation and verification of those controls.

## 3.3 Threat Model Table

| **Threat Area** | **ID** | **STRIDE** | **Component** | **Threat Title** | **Description & Impact** | **Risk** | **Risk Reasoning** | **Primary Control** |
|---|---|---|---|---|---|---|---|---|
| Authentication | T-01 | Spoofing | Customer Entity | Customer Identity Spoofing | An attacker impersonates a legitimate customer using stolen or brute-forced credentials to gain unauthorized access to payment actions and order history. **Impact:** Unauthorized account access; fraudulent payments or refund requests on behalf of the victim customer. | High | Authentication is the first line of defense at the public entry point. A compromised customer identity gives an attacker direct access to payment functions, making the impact financial and reputational. | OIDC authentication, token validation, TLS enforcement, WAF rules, account lockout. |
| Authentication | T-02 | Spoofing | Merchant Entity | Merchant Identity Spoofing | An attacker impersonates a merchant to issue unauthorized refunds, view financial transaction data, or manipulate settlement records. **Impact:** Direct financial loss through fraudulent merchant operations; potential exposure of other customers' transaction data. | High | Merchant accounts interact directly with financial workflows. API credential theft is a realistic attack vector, and the impact flows immediately into payment processing. | Centralized authentication, signed API tokens, MFA for merchant accounts. |
| Authentication | T-03 | Spoofing | Admin Entity | Administrative Identity Spoofing | An attacker or malicious insider impersonates an administrator to gain full control over system configuration, user management, and financial adjustments. **Impact:** Full system compromise; unauthorized financial adjustments; potential exfiltration of all sensitive data. | High | Admin accounts have the highest privilege in the system. A single compromised admin identity can affect every other security control, making this the highest-impact authentication threat. | VPN + MFA + dedicated Admin IdP; PAM session recording; IP-restricted admin access. |
| Authorization | T-04 | Elevation of Privilege | API Gateway | Privilege Escalation via Token Impersonation | A malicious actor exploits weaknesses in token validation at the API Gateway to impersonate a higher-privileged user, bypassing authorization controls. **Impact:** Broader API access than permitted; potential access to admin-level operations from a standard user account. | High | The API Gateway is the single enforcement point for all external requests. A bypass here invalidates all downstream authorization assumptions and exposes the entire backend. | JWT validation, RBAC/ABAC policy enforcement, gateway-level access control, token revocation list. |
| Authorization | T-05 | Elevation of Privilege | Payment Service | Payment Service Privilege Escalation | The Payment Service is exploited to impersonate a consumer or elevated service identity, enabling unauthorized transaction processing. **Impact:** Fraudulent payment processing or token misuse; unauthorized captures or refunds affecting financial integrity. | High | The Payment Service sits at the core of the financial workflow. Privilege escalation here enables direct financial fraud without triggering normal authentication controls. | mTLS between services; strict service identity controls; least-privilege service accounts. |
| Data Storage | T-06 | Spoofing | Transaction/Billing Database | Transaction Database Spoofing | The Transaction/Billing Database is spoofed or replaced by a fraudulent data store, causing backend services to write to or read from attacker-controlled storage. **Impact:** Financial record corruption; incorrect settlement data; loss of billing integrity. | High | The Transaction Database is the authoritative record of all financial activity. Spoofing it breaks the foundational trust relationship between the application and its data, with direct financial consequences. | Private Data Zone isolation; strict service-to-DB identity verification; TLS on DB connections. |
| Data Storage | T-07 | Tampering | Transaction/Billing Database | Transaction Record Manipulation | A privileged insider or compromised service account directly modifies transaction records in the database, altering payment history or settlement figures. **Impact:** Financial fraud; audit trail inconsistency; regulatory non-compliance; incorrect settlement to merchants. | High | Direct database write access is restricted but not zero. A privileged insider with DB access could alter records in ways that bypass application-layer controls, making detection dependent on audit log integrity. | Immutable audit log (WORM); RBAC restricting direct DB write access; SIEM alerting on anomalous DB writes. |
| API Communication | T-08 | Elevation of Privilege | Webhook Handler | Webhook Handler Impersonation | A malicious actor forges payment confirmation callbacks to the Webhook Handler, tricking the system into marking transactions as confirmed when payment was never received. **Impact:** Fraudulent settlement confirmations; revenue manipulation; merchants paid for transactions that never completed. | High | The Webhook Handler is a secondary external entry point with direct influence over transaction state. Forged callbacks are a realistic and well-documented attack against payment systems. | HMAC signature verification on all inbound webhooks; allowlist of processor IP ranges; idempotency checks. |
| API Communication | T-09 | Denial of Service | API Gateway / API Backend | API Resource Exhaustion | An attacker floods the API Gateway or API Backend with requests, consuming resources beyond capacity and causing service degradation or a full outage. **Impact:** Loss of payment processing availability for all users; merchant revenue loss; SLA breach. | High | The API Gateway is the single entry point for all traffic. Without rate limiting controls, a volumetric attack can collapse the entire system. Availability is a core security objective for a payment platform. | Rate limiting at API Gateway; WAF DDoS protection; autoscaling; cloud-level DDoS mitigation transfer. |
| API Communication | T-10 | Denial of Service | Webhook Handler / Transaction DB | Webhook and Database Exhaustion | A flood of inbound webhook requests overwhelms the Webhook Handler or saturates the Transaction Database connection pool, delaying payment confirmations. **Impact:** Payment lifecycle disruption; delayed or missed settlement events; potential duplicate payment processing. | High | The Webhook Handler is an unauthenticated-at-network-level endpoint that must accept inbound traffic from the processor. Without rate controls, it is trivially exploitable for exhaustion attacks. | Rate limiting on webhook endpoint; async queue-based processing; DB connection pooling; idempotency keys. |
| Logging & Monitoring | T-11 | Tampering | Audit Log Store | Audit Log Tampering | A privileged attacker or insider modifies or deletes audit log entries to conceal unauthorized actions — such as administrative changes, fraudulent transactions, or data access events. **Impact:** Loss of forensic evidence; inability to detect or investigate security incidents; regulatory non-compliance; cover-up of financial fraud. | High | Audit logs are the primary mechanism for detecting and investigating insider threats and fraud. If logs can be modified, all other monitoring controls lose their reliability. The impact extends to legal and compliance obligations. | WORM/append-only audit log storage; write-protected log store outside application control plane; cryptographically signed log entries; SIEM alert on log anomalies. |
| Logging & Monitoring | T-12 | Denial of Service | SIEM / Audit Log Pipeline | Monitoring System Overload and Alert Suppression | An attacker generates a high volume of low-priority events to saturate the SIEM or audit log pipeline, causing genuine high-severity alerts to be delayed, dropped, or buried. **Impact:** Critical security events go undetected during the attack window; delayed incident response; attacker operates unobserved while flooding the monitoring stack. | High | A blind monitoring system is as dangerous as no monitoring at all. Alert flooding is a known attacker technique to mask simultaneous malicious activity. Given the financial sensitivity of this system, any monitoring gap creates significant risk. | Log ingestion rate limiting; prioritized alert queuing; separate high-severity alert channel; redundant log storage with overflow protection. |
| Administrative Access | T-13 | Elevation of Privilege | Admin Service | Unauthorized Administrative Command Execution | An attacker who gains access to the Admin Portal — through stolen credentials, session hijacking, or VPN compromise — executes privileged operations such as mass refund approvals or user account modifications. **Impact:** Unauthorized financial adjustments at scale; mass account takeover or deletion; system configuration manipulation affecting all users. | High | Administrative operations have no equivalent user-level counterpart — a single unauthorized admin action can affect thousands of accounts or millions in financial value. The admin plane is the highest-value target in the system. | VPN-only admin access; MFA on Admin IdP; RBAC with dual-approval for high-impact operations; PAM session recording; alerting on off-hours admin activity. |
| Administrative Access | T-14 | Repudiation | Admin Service / Audit Log Store | Administrative Action Repudiation | An administrator performs a sensitive action — such as approving a large refund or modifying settlement rules — and later denies having done so, exploiting gaps in audit trail coverage or log integrity. **Impact:** Inability to attribute financial changes to a responsible party; regulatory non-compliance; unresolved fraud investigations; erosion of internal accountability. | High | In a financial system, non-repudiation is a compliance requirement, not just a best practice. Without tamper-evident, per-action audit records attributed to specific admin identities, disputes over high-value actions cannot be resolved. | Cryptographically signed audit records per admin action; immutable WORM log store; PAM session recording with video; multi-party approval for high-value operations. |

## 3.4 Key Threat Observations

The analysis reveals several structural patterns in the threat landscape of this system:

- **Identity concentration risk:** Authentication threats (T-01 to T-03) represent the highest-probability attack vectors because the system's public entry points are internet-facing. A single compromised identity can propagate across multiple financial workflows before detection.
- **Authorization as the last technical barrier:** Once authentication is bypassed, the API Gateway (T-04) and Payment Service (T-05) are the only remaining authorization enforcement points. Misconfiguration at either layer exposes the entire financial pipeline.
- **Financial data integrity chain:** Transaction database threats (T-06, T-07) are particularly dangerous because financial records serve as the authoritative source of truth for settlement. Tampering is difficult to detect without immutable audit infrastructure in place.
- **Webhook as a blind spot:** The Webhook Handler (T-08, T-10) is a frequently underestimated attack surface. It accepts inbound traffic from an external party and directly influences transaction state — making cryptographic verification non-negotiable.
- **Monitoring as a security dependency:** T-11 and T-12 demonstrate that the monitoring stack itself is a threat target. An attacker who can suppress alerts or tamper with logs effectively disables the organization's ability to detect all other threats in this model.
- **Administrative access as the highest-value target:** T-13 and T-14 reflect that the admin plane combines maximum privilege with minimum oversight by default. A single unauthorized admin action can affect thousands of accounts or millions in financial value — making non-repudiation and access controls here critical.

---

# 4. Secure Architecture Design
![Task 4 Secured Architecture](task4.png)
## 4.1 Identity and Access Management

A centralized User Identity Provider (IdP) implementing OIDC/OAuth2 handles authentication for customers and merchants, eliminating credential sprawl and standardizing token issuance. A dedicated Admin IdP with mandatory multi-factor authentication governs administrative access, reflecting the higher impact of admin session compromise.

Authorization is enforced through a combined RBAC/ABAC Policy Engine applied consistently across all services. All access tokens are short-lived JWTs with a 15-minute expiry, paired with rotating refresh tokens maintained in a revocation list at the API Gateway. Privileged administrative and DBA access is channeled through a dedicated jump server with full session recording, managed through a Privileged Access Management (PAM) system.

## 4.2 Network Segmentation

The architecture enforces strict network zone separation. A WAF at the public edge filters malicious traffic — including OWASP Top 10 attack patterns — before it reaches core services. The Backend Services Zone is on a separate, internally-routed network segment unreachable from the internet. The Private Data Zone restricts database access to whitelisted backend service IP addresses only.

The Admin Plane is completely separated from customer and merchant traffic paths: administrators access the Admin Portal exclusively through a VPN with MFA, and no admin API routes overlap with user-facing endpoints. East-west traffic between internal microservices is encrypted using mutual TLS (mTLS). External payment processor integrations connect via a dedicated segment with strict egress and ingress filtering.

## 4.3 Data Protection

All data in transit is protected by TLS 1.2 at minimum, with TLS 1.3 preferred and weak cipher suites explicitly disabled. Communication with the payment processor uses mutual TLS to authenticate both parties at the transport layer. All databases are encrypted at rest using AES-256, with encryption keys managed by a dedicated Key Management System or Hardware Security Module.

Credit card data is tokenized immediately upon receipt in the Payment Service and never stored in raw form. Audit logs are maintained in an append-only WORM (Write Once, Read Many) store that application services have no ability to modify or delete. Backups are encrypted and tested monthly for restore integrity.

## 4.4 Secrets Management

No credentials, API keys, or signing secrets are embedded in source code or configuration files — enforced through pre-commit hooks and static analysis scanning in the CI/CD pipeline. All secrets are stored in a dedicated secrets vault with automatic rotation on a defined schedule and an emergency rotation procedure for suspected compromises.

## 4.5 Monitoring, Logging, and Alerting

A centralized SIEM aggregates logs from all subsystems, the API Gateway, WAF, firewall, and identity provider. Audit logs are append-only and stored in a write-protected log store outside the application control plane. Log masking policies prevent PII, credentials, and session tokens from appearing in log records.

Automated alerts are configured for: repeated authentication failures, privilege escalation events, off-hours administrative access, and bulk data export operations. Each admin action generates a cryptographically signed, timestamped audit record. A dedicated high-severity alert channel ensures critical events are not lost during high-volume periods. Incident response playbooks cover account takeover, payment fraud, and insider data exfiltration scenarios.

## 4.6 Secure Deployment

The CI/CD pipeline incorporates SAST scanning, dependency vulnerability analysis, and container image scanning before any artifact reaches staging. Infrastructure-as-Code templates are subject to automated policy checks to detect misconfiguration before deployment. Signed build artifacts and a mandatory approval gate — particularly for changes affecting the admin plane or payment service — reduce the risk of unauthorized deployments. All service accounts follow the principle of least privilege.

## 4.7 Defense-in-Depth Summary

Security controls are applied at each architectural layer to ensure that no single control failure results in full system compromise:

- **Edge layer** — WAF filtering OWASP Top 10 attack patterns before traffic enters the system.
- **Identity layer** — centralized IdP with OIDC/OAuth2; mandatory MFA for all administrative access.
- **Authorization layer** — RBAC/ABAC Policy Engine enforced at the API Gateway and across all backend services.
- **Network layer** — zone segmentation with whitelisted firewall rules; dedicated Admin Plane via VPN; mTLS between services.
- **Data layer** — AES-256 encryption at rest; TLS/mTLS in transit; card tokenization; WORM audit logs.
- **Operations layer** — SIEM with automated alerting; PAM with session recording; anomaly detection; dedicated high-severity alert channel.
- **Deployment layer** — CI/CD security scanning; signed artifacts; change approval gate; least-privilege service accounts.

---

# 5. Risk Treatment and Residual Risk

## 5.1 Risk Treatment Decisions

The following table documents the risk treatment decision for each identified threat, organized by threat area, with the rationale for that decision and the residual risk remaining after controls are applied.

| **ID** | **Threat** | **Threat Area** | **Risk** | **Treatment** | **Rationale** | **Residual Risk** |
|---|---|---|---|---|---|---|
| T-01 | Customer Identity Spoofing | Authentication | High | Mitigate | Identity-based threats at the public entry point require active technical controls — acceptance is not viable given the direct financial impact. | Low — residual risk from credential theft or phishing outside system control. |
| T-02 | Merchant Identity Spoofing | Authentication | High | Mitigate | Merchant accounts interact with financial workflows; signed tokens and centralized auth reduce the attack surface significantly. | Low — phishing and credential compromise of merchant users remain residual risks. |
| T-03 | Admin Identity Spoofing | Authentication | High | Mitigate | Admin compromise is the highest-impact scenario. VPN + MFA + dedicated IdP represent the minimum acceptable control baseline. | Medium — insider threat and compromised MFA devices cannot be eliminated through technical controls alone. |
| T-04 | API Gateway Privilege Escalation | Authorization | High | Mitigate | Gateway impersonation undermines all downstream authorization. Token validation and RBAC enforcement are mandatory. | Low — misconfiguration of RBAC policies remains a residual operational risk. |
| T-05 | Payment Service Escalation | Authorization | High | Mitigate | Service-to-service impersonation in the payment flow enables financial fraud. mTLS and service identity controls are essential. | Low — residual risk if internal network segmentation is misconfigured. |
| T-06 | Transaction DB Spoofing | Data Storage | High | Mitigate | Database-level spoofing breaks the core trust boundary. Private zone isolation and strict service identity controls are non-negotiable. | Low — risk remains in the event of a privileged insider abusing service credentials. |
| T-07 | Transaction Record Manipulation | Data Storage | High | Mitigate | Immutable audit logs and SIEM alerting provide detection; RBAC limits write access to authorized services only. | Medium — privileged insider abuse is residual; managed through HR controls and audit monitoring. |
| T-08 | Webhook Handler Impersonation | API Communication | High | Mitigate | Forged payment confirmations directly affect settlement. HMAC verification and IP allowlisting are straightforward controls. | Low — residual risk if the payment processor's signing keys are externally compromised. |
| T-09 | API Resource Exhaustion | API Communication | High | Mitigate + Transfer | Rate limiting and autoscaling reduce impact; large-scale DDoS protection transferred to the cloud infrastructure provider. | Medium — volumetric DDoS attacks may still degrade performance despite cloud-level mitigation. |
| T-10 | Webhook and DB Exhaustion | API Communication | High | Mitigate | Async queue-based processing decouples webhook intake from DB writes, preventing cascading failure under load. | Low — extremely high webhook volumes may still introduce brief processing delays. |
| T-11 | Audit Log Tampering | Logging & Monitoring | High | Mitigate | Log integrity is a compliance requirement. WORM storage and cryptographic signing are the definitive technical controls. | Low — residual risk if the storage provider itself is compromised at the infrastructure level. |
| T-12 | Monitoring System Overload | Logging & Monitoring | High | Mitigate | Alert flooding is a known evasion technique; prioritized queuing and a separate high-severity channel ensure critical events are not lost. | Low — extremely sophisticated flooding attacks may still introduce brief detection delays. |
| T-13 | Unauthorized Admin Command Execution | Admin Access | High | Mitigate | Admin operations carry the highest financial impact; VPN, MFA, dual-approval, and session recording are layered controls. | Medium — insider threat and social engineering of admin staff remain residual risks. |
| T-14 | Administrative Action Repudiation | Admin Access | High | Mitigate | Non-repudiation is a compliance requirement in financial systems; cryptographic signing and PAM recording provide tamper-evident attribution. | Low — residual risk if PAM session recording infrastructure itself is compromised. |

## 5.2 Residual Risk Drivers

After applying all technical controls, four categories of residual risk remain that cannot be fully eliminated through architecture alone:

- **Human and behavioral risk:** Social engineering, phishing campaigns, and insider misuse operate in the human domain and are inherently resistant to purely technical controls. Mitigated through MFA, PAM, security awareness training, and background screening — but not eliminated.
- **Configuration and operational risk:** Security mechanisms such as RBAC policies, firewall rules, and encryption settings require correct implementation and ongoing maintenance. Misconfiguration by IT staff is a persistent residual risk, managed through infrastructure-as-code, peer review of configuration changes, and automated policy checking.
- **Third-party dependency risk:** The system relies on external services — the payment processor, core banking system, cloud infrastructure provider, and notification gateway — whose internal security posture is not fully visible or controllable. Managed through contractual obligations, vendor security assessments, and API isolation, but supply chain risk cannot be fully eliminated.
- **Advanced and unknown threats:** Zero-day vulnerabilities in operating systems, middleware, or third-party libraries represent inherent risk in any production system. Managed through rapid patch response procedures, network segmentation to limit blast radius, and endpoint detection and response tooling.

Residual risk across all identified threats is reduced to an operationally acceptable level through the combination of defense-in-depth architecture, continuous monitoring, separation of privilege domains, and documented incident response procedures.

## 5.3 Accepted and Avoided Risks

In addition to the Mitigate and Transfer decisions in Section 5.1, two further treatment strategies apply: Accept and Avoid.

**Accepted Risks**

- **Advanced Persistent Threats and Zero-Day Vulnerabilities (Accept):** Unknown vulnerabilities in the OS, middleware, and third-party libraries represent an inherent risk no architecture can fully eliminate. Nation-state actors may possess zero-day exploits that bypass all implemented defenses. This risk is formally accepted and managed through rapid patch response, network segmentation to limit blast radius, EDR tooling, and continuous SIEM monitoring. The cost of fully eliminating this risk would exceed the operational benefit for a commercially deployed payment platform.

- **Residual Social Engineering Risk (Accept):** A residual probability exists that a determined spear-phishing campaign will succeed against a high-value target even after MFA enforcement and security awareness training. This is accepted because it cannot be technically eliminated — it is instead managed through the assumption of credential compromise, MFA as a second line of defense, and PAM session recording to contain the impact of any successful social engineering attempt.

**Avoided Risks**

- **Raw Payment Card Data Storage (Avoid):** The risk of raw card data exposure is avoided entirely by design. The Payment Service tokenizes card data immediately upon receipt and never writes raw card numbers, CVVs, or expiry dates to any database or log. By not storing what does not need to be stored, the entire class of data-at-rest card exposure threats is eliminated at the architectural level — more effective than encryption alone, and consistent with PCI DSS requirements.

- **Direct Public Database Access (Avoid):** The entire class of direct internet-to-database attacks — SQL injection from the internet, unauthenticated database enumeration, remote database exploits — is avoided by placing all databases in a private zone with no internet-reachable interfaces. No database is assigned a public IP address or accessible outside of whitelisted backend service connections. The risk is not mitigated; it is structurally prevented through network architecture.

---

# 6. Secure Architecture Summary

## 6.1 System Overview

The Online Payment Processing Application is a multi-layered, cloud-compatible platform handling customer payments, merchant operations, and banking settlement. It processes highly sensitive financial and personal data, and its architecture reflects the security requirements of a PCI DSS-aligned payment environment.

## 6.2 Key Architectural Decisions

- Layered network segmentation — Internet → WAF → API Gateway → Backend Services Zone → Private Data Zone — contains breach impact at each boundary.
- Single API Gateway as the exclusive external entry point, enforcing authentication, authorization, and rate limiting before any backend service is reached.
- Dedicated Admin Plane — VPN + MFA + separate IdP — completely isolated from customer and merchant access paths.
- WORM audit logging stored outside the application control plane, ensuring tamper-evident records for compliance and forensic analysis.
- mTLS for all service-to-service and payment processor communications, authenticating both endpoints at the transport layer.
- Webhook HMAC verification as a dedicated control for the secondary external entry point, preventing fraudulent payment confirmation injection.

## 6.3 Threat Landscape Summary

Fourteen threats were identified across all six required threat areas and five STRIDE categories: Spoofing, Tampering, Repudiation, Denial of Service, and Elevation of Privilege. The highest risk concentration lies in identity-based attacks and in threats targeting the payment orchestration layer, audit infrastructure, and administrative access plane. All identified threats are rated High, reflecting the financial sensitivity of the system. All have been assigned specific mitigation controls, and residual risks are documented, monitored, and accepted within operational risk tolerance.

## Assumptions and Limitations

- The platform is hypothetical and is not tied to a specific cloud provider.
- Security controls are architectural recommendations rather than verified production implementations.
- Risk ratings are qualitative and depend on the stated assumptions.
- Third-party payment processors and banking integrations remain external trust dependencies.
- PCI DSS, privacy, financial and regional regulatory requirements would require a separate formal compliance assessment.
- Threat modelling should be repeated after architectural, data-flow or integration changes.


---

*End of Report — Online Payment Processing Application Threat Model*
