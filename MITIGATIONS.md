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

## Mitigation Overview

| Mitigation ID | Name | Category | Effectiveness |
|---------------|------|----------|---------------|
| [SAF-M-1](mitigations/SAF-M-1/README.md) | Control/Data Flow Separation | Architectural Defense | High (Provable Security) |
| [SAF-M-2](mitigations/SAF-M-2/README.md) | Cryptographic Integrity for Tool Descriptions | Cryptographic Control | High |
| [SAF-M-3](mitigations/SAF-M-3/README.md) | AI-Powered Content Analysis | AI-Based Defense | Medium-High |
| [SAF-M-4](mitigations/SAF-M-4/README.md) | Unicode Sanitization and Filtering | Input Validation | Medium-High |
| [SAF-M-5](mitigations/SAF-M-5/README.md) | Content Sanitization | Input Validation | Medium |
| [SAF-M-6](mitigations/SAF-M-6/README.md) | Tool Registry Verification | Supply Chain Security | High |
| [SAF-M-7](mitigations/SAF-M-7/README.md) | Content Rendering Parity | UI Security | Medium-High |
| [SAF-M-8](mitigations/SAF-M-8/README.md) | Visual Validation | UI Security | Medium |
| [SAF-M-9](mitigations/SAF-M-9/README.md) | Sandboxed Testing | Isolation and Containment | High |
| [SAF-M-10](mitigations/SAF-M-10/README.md) | Automated Scanning | Detective Control | Medium |
| [SAF-M-11](mitigations/SAF-M-11/README.md) | Behavioral Monitoring | Detective Control | High |
| [SAF-M-12](mitigations/SAF-M-12/README.md) | Audit Logging | Detective Control | Medium-High |
| [SAF-M-13](mitigations/SAF-M-13/README.md) | OAuth Flow Verification | Preventive Control | High |
| [SAF-M-14](mitigations/SAF-M-14/README.md) | Server Allowlisting | Preventive Control | High |
| [SAF-M-15](mitigations/SAF-M-15/README.md) | User Warning Systems | Preventive Control | Medium |
| [SAF-M-16](mitigations/SAF-M-16/README.md) | Token Scope Limiting | Preventive Control | High |
| [SAF-M-17](mitigations/SAF-M-17/README.md) | Callback URL Restrictions | Preventive Control | High |
| [SAF-M-18](mitigations/SAF-M-18/README.md) | OAuth Flow Monitoring | Detective Control | Medium |
| [SAF-M-19](mitigations/SAF-M-19/README.md) | Token Usage Tracking | Detective Control | Medium |
| [SAF-M-20](mitigations/SAF-M-20/README.md) | Anomaly Detection | Detective Control | High |
| [SAF-M-21](mitigations/SAF-M-21/README.md) | Output Context Isolation | Architectural Control | High |
| [SAF-M-22](mitigations/SAF-M-22/README.md) | Semantic Output Validation | Input Validation | Medium-High |
| [SAF-M-23](mitigations/SAF-M-23/README.md) | Tool Output Truncation | Preventive Control | Medium |
| [SAF-M-24](mitigations/SAF-M-24/README.md) | SBOM Generation and Verification | Supply Chain Security | High |
| [SAF-M-25](mitigations/SAF-M-25/README.md) | AI-Specific Risk Modeling | Risk Management | Medium-High |
| [SAF-M-26](mitigations/SAF-M-26/README.md) | Data Provenance Tracking | Data Security | High |
| [SAF-M-27](mitigations/SAF-M-27/README.md) | Social Engineering Awareness Training | Human Factors | Medium |
| [SAF-M-28](mitigations/SAF-M-28/README.md) | Pre-Authentication Tool Concealment | Preventive Control | High |
| [SAF-M-30](mitigations/SAF-M-30/README.md) | Vector Store Integrity Verification | Cryptographic Control | High |
| [SAF-M-32](mitigations/SAF-M-32/README.md) | Continuous Vector Store Monitoring | Detective Control | Medium-High |
| [SAF-M-33](mitigations/SAF-M-33/README.md) | Training Data Provenance Verification | Data Security | High |
| [SAF-M-34](mitigations/SAF-M-34/README.md) | AI Model Integrity Validation | Cryptographic Control | High |
| [SAF-M-35](mitigations/SAF-M-35/README.md) | Adversarial Training Data Detection | AI-Based Defense | Medium-High |
| [SAF-M-36](mitigations/SAF-M-36/README.md) | Model Behavior Monitoring | Detective Control | Medium-High |
| [SAF-M-29](mitigations/SAF-M-29/README.md) | Explicit Privilege Boundaries | Architectural Control | High |
| [SAF-M-37](mitigations/SAF-M-37/README.md) | Metadata Sanitization | Input Validation | High |
| [SAF-M-38](mitigations/SAF-M-38/README.md) | Schema Validation | Input Validation | Medium-High |
| [SAF-M-39](mitigations/SAF-M-39/README.md) | Prompt Context Validation | Architectural Control | High |
| [SAF-M-40](mitigations/SAF-M-40/README.md) | Clear UI Patterns | UI Security | Medium-High |
| [SAF-M-41](mitigations/SAF-M-41/README.md) | Tool and Package Pinning | Supply Chain Control | High |
| [SAF-M-42](mitigations/SAF-M-42/README.md) | Cross-Server Protection | Architectural Control | High |
| [SAF-M-43](mitigations/SAF-M-43/README.md) | Steganography Scanner | Detective Control | Medium-High |
| [SAF-M-44](mitigations/SAF-M-44/README.md) | Behavioural Monitoring | Detective Control | Medium-High |
| [SAF-M-45](mitigations/SAF-M-45/README.md) | Tool Manifest Signing & Server Attestation | Supply Chain Security | High |
| [SAF-M-46](mitigations/SAF-M-46/README.md) | Bridge Risk Management | Preventive Control | High |
| [SAF-M-47](mitigations/SAF-M-47/README.md) | Cross-Chain Transaction Graph Analysis | Detective Control | High |
| [SAF-M-48](mitigations/SAF-M-48/README.md) | Custodial Off-Ramp Monitoring | Detective Control | Medium-High |


## Summary Statistics

- **Total Mitigations**: 47
- **High Effectiveness**: 26 (55%)
- **Medium-High Effectiveness**: 15 (32%)
- **Medium Effectiveness**: 6 (13%)
- **Low Effectiveness**: 0 (0%)

## Category Distribution

| Category | Number of Mitigations |
|----------|---------------------|
| Detective Control | 12 |
| Preventive Control | 7 |
| Input Validation | 6 |
| Cryptographic Control | 3 |
| Architectural Defense | 2 |
| UI Security | 3 |
| AI-Based Defense | 2 |
| Supply Chain Security | 4 |
| Data Security | 2 |
| Architectural Control | 4 |
| Isolation and Containment | 1 |
| Risk Management | 1 |
| Human Factors | 1 |


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
3. Update this MITIGATIONS.md file
4. Submit a pull request with justification for the new mitigation
