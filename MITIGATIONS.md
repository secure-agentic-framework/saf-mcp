# SAF-MCP Mitigations Reference

## About SAF-MCP Mitigations

SAF-MCP mitigations are security controls designed to protect Model Context Protocol (MCP) implementations from the attack techniques documented in our framework. Each mitigation is categorized by type and effectiveness, with clear mappings to the techniques it addresses.

### Licensing

New contributions to the mitigations are licensed under the [Community Specification License 1.0](LICENSE-CSL-1.0). Mitigation content contributed on or before 2026-06-10 remains under [CC BY 4.0](LICENSE-CC-BY-4.0) until the original contributors sign off on relicensing or the content is rewritten. See [LICENSE](LICENSE) for the full licensing structure.

### Mitigation Categories

- **Architectural Defense**: Fundamental design patterns that prevent entire classes of attacks
- **Cryptographic Control**: Security measures using cryptographic techniques
- **AI-Based Defense**: Controls leveraging AI/ML for detection and prevention
- **Input Validation**: Sanitization and validation of inputs before processing
- **Supply Chain Security**: Controls for securing the MCP software supply chain
- **UI Security**: Controls ensuring visual consistency and preventing deception
- **Isolation and Containment**: Sandboxing and isolation techniques
- **Detective Control**: Monitoring and detection capabilities
- **Preventive Control**: Controls that prevent attacks before they occur
- **Architectural Control**: System design patterns for security

### Effectiveness Ratings

- **High**: Highly effective control, prevents 80%+ of targeted attacks
- **Medium-High**: Effective control, prevents 60-80% of targeted attacks
- **Medium**: Moderately effective, prevents 40-60% of targeted attacks
- **Low**: Limited effectiveness, prevents <40% of targeted attacks

<!-- BEGIN GENERATED SAF MITIGATION CATALOG -->
## Mitigation Catalog

This generated inventory lists the mitigation documents that exist in the repository. It does not independently validate the effectiveness claims within those documents.

| Mitigation ID | Document title |
| --- | --- |
| [SAF-M-1](mitigations/SAF-M-1/README.md) | Architectural Defense - Control/Data Flow Separation |
| [SAF-M-2](mitigations/SAF-M-2/README.md) | Cryptographic Integrity for Tool Descriptions |
| [SAF-M-3](mitigations/SAF-M-3/README.md) | AI-Powered Content Analysis |
| [SAF-M-4](mitigations/SAF-M-4/README.md) | Unicode Sanitization and Filtering |
| [SAF-M-5](mitigations/SAF-M-5/README.md) | Content Sanitization |
| [SAF-M-6](mitigations/SAF-M-6/README.md) | Tool Registry Verification |
| [SAF-M-7](mitigations/SAF-M-7/README.md) | Content Rendering Parity |
| [SAF-M-8](mitigations/SAF-M-8/README.md) | Visual Validation |
| [SAF-M-9](mitigations/SAF-M-9/README.md) | Sandboxed Testing |
| [SAF-M-10](mitigations/SAF-M-10/README.md) | Automated Scanning |
| [SAF-M-11](mitigations/SAF-M-11/README.md) | Behavioral Monitoring |
| [SAF-M-12](mitigations/SAF-M-12/README.md) | Audit Logging |
| [SAF-M-13](mitigations/SAF-M-13/README.md) | OAuth Flow Verification |
| [SAF-M-14](mitigations/SAF-M-14/README.md) | Server Allowlisting |
| [SAF-M-15](mitigations/SAF-M-15/README.md) | User Warning Systems |
| [SAF-M-16](mitigations/SAF-M-16/README.md) | Token Scope Limiting |
| [SAF-M-17](mitigations/SAF-M-17/README.md) | Callback URL Restrictions |
| [SAF-M-18](mitigations/SAF-M-18/README.md) | OAuth Flow Monitoring |
| [SAF-M-19](mitigations/SAF-M-19/README.md) | Token Usage Tracking |
| [SAF-M-20](mitigations/SAF-M-20/README.md) | Anomaly Detection |
| [SAF-M-21](mitigations/SAF-M-21/README.md) | Output Context Isolation |
| [SAF-M-22](mitigations/SAF-M-22/README.md) | Semantic Output Validation |
| [SAF-M-23](mitigations/SAF-M-23/README.md) | Tool Output Truncation |
| [SAF-M-24](mitigations/SAF-M-24/README.md) | Supply Chain Security - SBOM Generation and Verification |
| [SAF-M-29](mitigations/SAF-M-29/README.md) | Explicit Privilege Boundaries |
| [SAF-M-30](mitigations/SAF-M-30/README.md) | Vector Store Integrity Verification |
| [SAF-M-31](mitigations/SAF-M-31/README.md) | Proof of Possession (PoP) Tokens |
| [SAF-M-32](mitigations/SAF-M-32/README.md) | Continuous Vector Store Monitoring |
| [SAF-M-33](mitigations/SAF-M-33/README.md) | Training Data Provenance Verification |
| [SAF-M-34](mitigations/SAF-M-34/README.md) | AI Model Integrity Validation |
| [SAF-M-35](mitigations/SAF-M-35/README.md) | Adversarial Training Data Detection |
| [SAF-M-36](mitigations/SAF-M-36/README.md) | Model Behavior Monitoring |
| [SAF-M-37](mitigations/SAF-M-37/README.md) | Token Rotation and Invalidation |
| [SAF-M-38](mitigations/SAF-M-38/README.md) | PKCE Enforcement |
| [SAF-M-44](mitigations/SAF-M-44/README.md) | Tool Definition Integrity Monitoring |
| [SAF-M-45](mitigations/SAF-M-45/README.md) | Tool Manifest Signing & Server Attestation |
| [SAF-M-46](mitigations/SAF-M-46/README.md) | Bridge Risk Management |
| [SAF-M-47](mitigations/SAF-M-47/README.md) | Cross-Chain Transaction Graph Analysis |
| [SAF-M-48](mitigations/SAF-M-48/README.md) | Custodial Off-Ramp Monitoring |
| [SAF-M-49](mitigations/SAF-M-49/README.md) | Multimedia Content Sanitization |
| [SAF-M-50](mitigations/SAF-M-50/README.md) | OCR Security Scanning |
| [SAF-M-51](mitigations/SAF-M-51/README.md) | Embedding Anomaly Detection |
| [SAF-M-52](mitigations/SAF-M-52/README.md) | Input Validation Pipeline |
| [SAF-M-53](mitigations/SAF-M-53/README.md) | Multimodal Behavioral Monitoring |
| [SAF-M-54](mitigations/SAF-M-54/README.md) | Cross-Modal Correlation Analysis |
| [SAF-M-63](mitigations/SAF-M-63/README.md) | Embedding-Based API Key Detection and Filtering |
| [SAF-M-69](mitigations/SAF-M-69/README.md) | Out-of-Band Authorization for Privileged Tool Invocations |
| [SAF-M-70](mitigations/SAF-M-70/README.md) | Detective Control - Tool-Invocation Anomaly Detection & Baselining |
| [SAF-M-71](mitigations/SAF-M-71/README.md) | Query Guardrails & Result Limits |
| [SAF-M-72](mitigations/SAF-M-72/README.md) | Data Security - Data Loss Prevention on Tool Outputs |
| [SAF-M-73](mitigations/SAF-M-73/README.md) | Sampling Budget and Iteration Caps |
| [SAF-M-74](mitigations/SAF-M-74/README.md) | Per-Invocation Capability Brokering |

**Total mitigation documents:** 52
<!-- END GENERATED SAF MITIGATION CATALOG -->

## Implementation Guidance

### Defense in Depth Strategy

The most effective security posture combines multiple mitigations across different categories:

1. **Foundation Layer**: Implement architectural defenses (SAF-M-1, SAF-M-21) that provide fundamental protection
2. **Prevention Layer**: Add cryptographic controls (SAF-M-2) and input validation (SAF-M-4, SAF-M-5, SAF-M-22)
3. **Detection Layer**: Deploy monitoring and detection controls (SAF-M-10, SAF-M-11, SAF-M-12)
4. **Response Layer**: Maintain audit logs and incident response procedures

### Priority Implementation

For organizations with limited resources, prioritize implementation based on:

1. **Critical Controls** (Implement First):
   - SAF-M-1: Control/Data Flow Separation
   - SAF-M-2: Cryptographic Integrity
   - SAF-M-6: Tool Registry Verification
   - SAF-M-11: Behavioral Monitoring

2. **Important Controls** (Implement Second):
   - SAF-M-3: AI-Powered Content Analysis
   - SAF-M-4: Unicode Sanitization
   - SAF-M-9: Sandboxed Testing
   - SAF-M-13: OAuth Flow Verification

3. **Additional Controls** (Implement as Resources Allow):
   - Remaining mitigations based on specific threat model


## Usage Guidelines

- Review mitigations relevant to your threat model
- Implement controls in layers for defense in depth
- Regularly update and test mitigation effectiveness
- Monitor for new threats requiring additional controls
- Consider automation for detective controls
- Document implementation details for compliance

## Contributing

To add new mitigations or update existing ones:
1. Create a new directory under `mitigations/` with the next available SAF-M-X number
2. Use the mitigation template for consistent documentation
3. Run `python3 scripts/generate-mitigation-catalog.py`
4. Submit a pull request with justification for the new mitigation
