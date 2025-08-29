# Deployment Strategy

## **Proposed Solution:** Multi-Tiered Defense with Edge Processing

To properly address the security vulnerability revealed in the audit, we must build a robust and efficient **defense-in-depth** strategy. The result of "Project Guardian 2.0" will be a implementive PII redaction plugin implemented at the **API Gateway layer**.

This strategic positioning enables us to capture and cleanse all data in transit inclusive of both incoming and outgoing at the network perimeter, *before* sensitive information can be recorded by internal services or exposed via external API integrations. This directly tackles the fundamental issue of the recent incident. By managing data streams at this critical state, we guarantee uniform policy enforcement across all microservices, thereby fulfilling the necessity for expensive and inconsistent modifications to each individual application.

---

### **Architecture & Design**

This architecture is engineered for minimal latency impact and enhanced scalability.

*   **Leveraging Existing Infrastructure:** Utilizing the current API Gateway infrastructure (e.g., an **NGINX Lua script**) allows us to inject redaction logic directly into the request/response lifecycle, avoiding additional network hops.
*   **Stateless & Scalable:** The stateless design of the detection mechanism allows it to scale horizontally, and helps in effortlessly managing traffic surges.
*   **Cost-Effective & Simple:** This method is more economical and operationally straightforward.

---

### **Phased Deployment Plan**

The implementation is proposed to be deployed in three sequential phases.

1.  **Phase 1: Shadow Mode | Alpha**
    *   The plugin processes live traffic in parallel without modifying any data.
    *   **Goal:** Assess false positive/negative rates against real production workloads to fine-tune detection rules(if IDS is available).

2.  **Phase 2: Test Release | Beta**
    *   Active redaction is enabled for a small or beta clients, controlled percentage of traffic (e.g., 5-10%).
    *   **Goal:** Actively observe system performance, latency, and error rates before a full rollout.
    *   **Observation:** There are certain functions/modules which forcibly require raw data.

3.  **Phase 3: Full Deployment**
    *   Comprehensive deployment to 100% of production traffic.
    *   **Goal:** A real-time dashboard is deployed for continuous monitoring of detection precision and system integrity.
    *   **Risk Mitigation:** Circuit breakers are implemented to automatically bypass the plugin during instances of high latency or failures, safeguarding the core platform's availability.

---

### **PS**

**Data at Rest Security:** Integration with our existing **Data Loss Prevention (DLP)** (as mentioned in the problem statement) tool will establish a final safety net through periodic scans of data in databases and file storage, creating a thorough, hybrid shield for customer data throughout its entire lifecycle and even after deployment.

---

### **References**

1.  IBM API LTS" *Redaction*. [https://www.ibm.com/docs/en/api-connect/10.0.8_lts](https://www.ibm.com/docs/en/api-connect/10.0.8_lts?topic=cvcad-messages-generated-during-conversion-apis-datapower-api-gateway#REDACT)