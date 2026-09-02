# SAF-MCP: Secure Agentic Framework for Model Context Protocol

| SIG-SAF-MCP      | Details                                                                                    |
| ---------------- | ------------------------------------------------------------------------------------------ |
| **Mailing List** | [openssf-sig-safe-mcp@lists.openssf.org](https://lists.openssf.org/g/openssf-sig-safe-mcp) |
| **SIG Leads**    | Sarah Evans; Frederick Kautz                                                               |
| **Maintainers**  | Bishnu Bista; Sarah Evans; Frederick Kautz                                                 |
| **Meeting Time** | 1:00 PM PT (PST/PDT) Bi-Weekly                                                             |
| **Slack**        | OpenSSF #sig-safe-mcp                                                                      |

## About SAF-MCP

The Secure Agentic Framework (SAF) documents adversary behavior in agentic systems. SAF-MCP is the project and MCP profile: the same permanent technique IDs can also be scoped to SAF Core, Code-Agent, RAG and Memory, Financial-Agent, and Model-Lifecycle profiles. [Framework Model v2](research/FRAMEWORK-MODEL.md) defines the admission, lifecycle, relationship, and release rules.

### Key Features

- **Atomic, Permanent Techniques**: IDs represent distinct adversary behaviors and remain permanent even when an entry is consolidated or deprecated.
- **Profile-Based Scope**: SAF separates general agentic mechanisms from MCP and other domain-specific profiles without duplicating technique IDs.
- **Typed Relationships**: Technique links distinguish specializations, prerequisites, sequence, overlap, alternatives, and replacements.
- **MITRE ATT&CK Alignment**: Where defensible, SAF techniques link to relevant MITRE ATT&CK behaviors to support threat modeling, detection engineering, and cross-framework analysis. These mappings do not establish compliance.
- **Evidence-Led Releases**: Evidence, taxonomy, and operational gates require traceable claims, coherent placement, and tested or explicitly bounded detection.
- **Operational Coverage Registry**: The generated [detection coverage matrix](detections/COVERAGE.md) separates technique linkage, observation modality, validation maturity, and external rule ownership.
- **Actionable Mitigations**: Each technique includes detailed mitigation strategies and detection rules to help defenders protect their MCP deployments.

### How to Use This Framework

1. **Security Teams**: Select the profiles that match your agentic deployment, then use the catalog below to build a threat model
2. **Developers**: Review techniques relevant to the agents, models, data paths, and tools you operate and implement the linked mitigations
3. **Compliance Officers**: Map SAF-MCP techniques to your existing security controls via MITRE ATT&CK linkages
4. **Red Teams**: Reference attack techniques for security testing of MCP deployments

## TTP Reference Table

The generated catalog below is the public projection of the canonical Framework Model v2 registry.

<!-- BEGIN GENERATED SAF TECHNIQUE CATALOG -->
## SAF Tactics

SAF uses 14 ATT&CK-aligned adversary objectives. The canonical machine-readable catalog is [`research/framework-model.yml`](research/framework-model.yml); its admission and lifecycle rules are defined in [Framework Model v2](research/FRAMEWORK-MODEL.md).

| Tactic ID | Tactic | Active Techniques | Description |
| --- | --- | ---: | --- |
| ATK-TA0043 | Reconnaissance | 0 | The adversary is gathering information to plan future agentic operations. |
| ATK-TA0042 | Resource Development | 1 | The adversary is establishing resources to support agentic operations. |
| ATK-TA0001 | Initial Access | 9 | The adversary is trying to enter an agentic environment. |
| ATK-TA0002 | Execution | 8 | The adversary is trying to cause code, tools, or model-mediated actions to run. |
| ATK-TA0003 | Persistence | 6 | The adversary is trying to retain influence or access across agent sessions or restarts. |
| ATK-TA0004 | Privilege Escalation | 8 | The adversary is trying to exercise authority beyond the initiating principal or task. |
| ATK-TA0005 | Defense Evasion | 8 | The adversary is trying to avoid prevention, review, or detection. |
| ATK-TA0006 | Credential Access | 7 | The adversary is trying to obtain authentication material or delegated authority. |
| ATK-TA0007 | Discovery | 6 | The adversary is trying to understand an agentic environment after gaining access. |
| ATK-TA0008 | Lateral Movement | 7 | The adversary is trying to move between tools, agents, services, or trust domains. |
| ATK-TA0009 | Collection | 5 | The adversary is gathering data of interest through an agentic system. |
| ATK-TA0011 | Command and Control | 4 | The adversary is maintaining a control or feedback path through an agentic system. |
| ATK-TA0010 | Exfiltration | 6 | The adversary is removing data through an agentic system or connected service. |
| ATK-TA0040 | Impact | 7 | The adversary is manipulating, interrupting, or destroying systems, assets, or decisions. |

## SAF Profiles

Profiles scope an atomic technique without changing its permanent ID. A technique may appear in more than one profile.

| Profile | Active Techniques | Scope |
| --- | ---: | --- |
| SAF Core | 31 | Mechanisms that materially depend on model-mediated decisions, delegated action, dynamic context, memory, or agent coordination. |
| MCP Profile | 76 | Mechanisms expressed through Model Context Protocol hosts, clients, servers, tools, resources, prompts, sampling, authorization, or transports. |
| Code-Agent Profile | 12 | Mechanisms specific to coding assistants, developer workstations, repositories, build systems, shells, and file-oriented agents. |
| RAG and Memory Profile | 5 | Mechanisms involving retrieval indexes, embeddings, persistent context, shared memory, or retrieval-augmented generation. |
| Financial-Agent Profile | 2 | Mechanisms involving delegated payment, trading, blockchain, or other financial authority. |
| Model-Lifecycle Profile | 1 | Mechanisms involving training, adaptation, evaluation, registration, promotion, or deployment of model artifacts. |

## Active Technique Catalog

Techniques are listed under every applicable tactic; counts therefore represent tactic mappings, not unique IDs.

| Tactic | Technique | Name | Profiles | Description |
| --- | --- | --- | --- | --- |
| Reconnaissance | — | — | — | No active techniques currently admitted. |
| Resource Development | [SAF-T2107](techniques/SAF-T2107/README.md) | AI Model Poisoning via MCP Tool Training Data Contamination | MCP Profile, Model-Lifecycle Profile | This technique covers adversary-controlled MCP tool results that cross from live tool execution into a corpus used to update model weights, causing the derived model to learn attacker-influenced behavior. |
| Initial Access | [SAF-T1001](techniques/SAF-T1001/README.md) | Tool Poisoning Attack | SAF Core, MCP Profile | SAF-T1001 covers attacker-controlled instructions or policy embedded in an MCP tool definition—principally its natural-language description or parameter schema—that crosses from a server-controlled discovery response into the host/model planning context and causes tool selection or arguments contrary to the user's intent. |
| Initial Access | [SAF-T1002](techniques/SAF-T1002/README.md) | Supply Chain Compromise | MCP Profile | This technique covers an adversary altering a component or release path that consumers reasonably treat as the authentic upstream, then causing an MCP or agentic deployment to install, load, import, update, or execute the altered artifact. |
| Initial Access | [SAF-T1003](techniques/SAF-T1003/README.md) | Malicious MCP-Server Distribution | MCP Profile | In scope are initial malicious publication, delivery of a malicious release through a package or MCP registry, marketplace, release location, direct configuration, or remote endpoint, and continued availability through a private mirror or cache after public takedown. |
| Initial Access | [SAF-T1004](techniques/SAF-T1004/README.md) | Server Impersonation / Name-Collision | MCP Profile | The frozen technique contract covers wrong-server selection caused by an ambiguous, colliding, lookalike, self-asserted, or insufficiently authenticated server identity. |
| Initial Access | [SAF-T1005](techniques/SAF-T1005/README.md) | Exposed Endpoint Exploit | MCP Profile | Exposed Endpoint Exploit covers an untrusted network client or browser origin reaching an MCP endpoint, proxy, or management endpoint whose exposure and missing or bypassed access controls permit an unauthorized capability invocation. |
| Initial Access | [SAF-T1006](techniques/SAF-T1006/README.md) | User-Social-Engineering Install | MCP Profile | This technique covers deception that causes a user to initiate or approve an attacker-controlled local MCP server installation, configuration, trust decision, or first launch, crossing the user-to-local-runtime boundary. |
| Initial Access | [SAF-T1007](techniques/SAF-T1007/README.md) | OAuth Authorization Phishing | MCP Profile | This technique covers forwarding an MCP-generated third-party OAuth authorization URL to a different user so that the victim completes authorization while the MCP server binds the resulting tokens to the attacker's initiating session. |
| Initial Access | [SAF-T1008](techniques/SAF-T1008/README.md) | Cross-Server Tool Shadowing | SAF Core, MCP Profile | Tool shadowing is cross-server descriptor interference: text supplied for an attacker-controlled tool changes how an agent selects, configures, or invokes a distinct tool from a trusted server. |
| Initial Access | [SAF-T1009](techniques/SAF-T1009/README.md) | Authorization Server Mix-up | MCP Profile | This technique covers an attacker-controlled or compromised authorization server causing a multi-authorization-server MCP client to misattribute a browser-delivered response from an honest issuer and send the resulting code or token to the attacker-controlled server. |
| Execution | [SAF-T1101](techniques/SAF-T1101/README.md) | Command Injection | MCP Profile, Code-Agent Profile | The defining security boundary lies between untrusted MCP-derived data or configuration and a shell, interpreter, or direct process-launch API used by a host, client, server, proxy, or tool. |
| Execution | [SAF-T1102](techniques/SAF-T1102/README.md) | Prompt Injection (Multiple Vectors) | SAF Core, MCP Profile | Prompt Injection (Multiple Vectors) covers attacker-controlled natural-language or multimodal instructions that enter model context and cause the model to treat untrusted content as authoritative directions. |
| Execution | [SAF-T1103](techniques/SAF-T1103/README.md) | Fake Tool Invocation (Function Spoofing) | MCP Profile | This technique covers execution caused by treating an attacker-originated tool-call record, or an attacker-influenced callable identity, as if it were an authorized call from the trusted agent workflow. |
| Execution | [SAF-T1105](techniques/SAF-T1105/README.md) | Path Traversal via File Tool | MCP Profile, Code-Agent Profile | This technique covers an MCP or agent file-capable tool when attacker-influenced path data resolves beyond the configured file scope, or bypasses a no-access mode, and the tool attempts a filesystem operation. |
| Execution | [SAF-T1106](techniques/SAF-T1106/README.md) | Autonomous Loop Exploit | SAF Core, MCP Profile | The security boundary is the handoff from untrusted or attacker-influenced content into an autonomous orchestrator's continuation decision. |
| Execution | [SAF-T1110](techniques/SAF-T1110/README.md) | Multimodal Prompt Injection via Images/Audio | SAF Core, MCP Profile | This technique covers attacker-controlled instructions carried by image or audio data that a multimodal model treats as executable guidance, crossing the boundary between untrusted media and trusted agent decisions. |
| Execution | [SAF-T1111](techniques/SAF-T1111/README.md) | AI Agent CLI Weaponization | SAF Core, Code-Agent Profile | This technique covers an adversary deliberately operating an AI coding-agent command-line interface as the execution and orchestration layer for malicious actions against real targets, crossing from model-mediated tasking into commands or tools that act on target systems. |
| Execution | [SAF-T1112](techniques/SAF-T1112/README.md) | Sampling Request Abuse | SAF Core, MCP Profile | This technique applies only where an MCP client supports server-initiated sampling/createMessage, accepts the request, and lacks sufficient approval, context, or budget controls. |
| Persistence | [SAF-T1201](techniques/SAF-T1201/README.md) | Post-Approval Tool Mutation | MCP Profile | This technique covers a time-of-check/time-of-use trust reversal in which an MCP server, provider, or update channel first presents a benign tool definition, gains approval, and later changes the same approved tool's metadata or delivered implementation so the host consumes materially different behavior without renewed authorization. |
| Persistence | [SAF-T1202](techniques/SAF-T1202/README.md) | OAuth Token Persistence | MCP Profile | This technique covers an adversary using an attacker-controlled OAuth refresh token to obtain replacement access tokens for an MCP protected resource, preserving the existing client, subject, scope, and resource grant across access-token lifetimes. |
| Persistence | [SAF-T1203](techniques/SAF-T1203/README.md) | Backdoored Server Binary | MCP Profile, Code-Agent Profile | This technique covers post-approval or post-deployment replacement, patching, or infection of a configured MCP server executable or a support binary it directly loads. |
| Persistence | [SAF-T1204](techniques/SAF-T1204/README.md) | Context Memory Implant | SAF Core, MCP Profile, RAG and Memory Profile | This technique covers an adversary causing selected content to be written into an agent's persistent context memory so that retrieval in a later session influences reasoning, a response, planning, or a tool decision. |
| Persistence | [SAF-T1206](techniques/SAF-T1206/README.md) | Credential Implant in Config | MCP Profile, Code-Agent Profile | This technique covers an adversary writing or replacing a credential, credential reference, or client-registration identity in persistent MCP or agent configuration so later connections authenticate with an attacker-selected identity. |
| Persistence | [SAF-T1207](techniques/SAF-T1207/README.md) | Hijack Update Mechanism | MCP Profile | SAF-T1207 covers an adversary causing the normal update path of an already trusted MCP or agentic component to accept and activate an attacker-selected replacement, preserving adversary-controlled code across restarts. |
| Privilege Escalation | [SAF-T1008](techniques/SAF-T1008/README.md) | Cross-Server Tool Shadowing | SAF Core, MCP Profile | Tool shadowing is cross-server descriptor interference: text supplied for an attacker-controlled tool changes how an agent selects, configures, or invokes a distinct tool from a trusted server. |
| Privilege Escalation | [SAF-T1009](techniques/SAF-T1009/README.md) | Authorization Server Mix-up | MCP Profile | This technique covers an attacker-controlled or compromised authorization server causing a multi-authorization-server MCP client to misattribute a browser-delivered response from an honest issuer and send the resulting code or token to the attacker-controlled server. |
| Privilege Escalation | [SAF-T1302](techniques/SAF-T1302/README.md) | Agentic Confused Deputy | SAF Core, MCP Profile | Agentic Confused Deputy covers a low-trust requestor or untrusted input causing an agent to exercise a legitimate tool, service identity, or approved process with authority unavailable to that principal because requestor authorization, scope binding, or action-bound approval is absent or ineffective. |
| Privilege Escalation | [SAF-T1303](techniques/SAF-T1303/README.md) | Sandbox Escape via Server Exec | MCP Profile, Code-Agent Profile | This technique covers attacker-controlled MCP configuration or tool input reaching a server-side process launcher and escaping the caller's intended sandbox or authorization boundary into a more-privileged service, container, or host context. |
| Privilege Escalation | [SAF-T1304](techniques/SAF-T1304/README.md) | Credential Relay Chain | MCP Profile | Credential Relay Chain covers an MCP or agent intermediary causing a credential to cross a resource, principal, or hop boundary without independent issuance and validation for the current caller and target, so the receiving component authorizes greater access than the caller otherwise has. |
| Privilege Escalation | [SAF-T1305](techniques/SAF-T1305/README.md) | Host OS Priv-Esc (RCE) | MCP Profile, Code-Agent Profile | This technique covers exploitation of an MCP host-side client, proxy, inspector, or server flaw that changes an attacker's authority from MCP-level or low-privileged interaction to arbitrary host operating-system code execution in the vulnerable process account. |
| Privilege Escalation | [SAF-T1307](techniques/SAF-T1307/README.md) | Confused Deputy Attack | MCP Profile | This technique covers an attacker causing an MCP or agentic intermediary to use authority, identity, network reach, or execution capability unavailable to the attacker because the intermediary fails to preserve or enforce the initiating principal's identity, resource, authorization intent, or approved delegation. |
| Privilege Escalation | [SAF-T1308](techniques/SAF-T1308/README.md) | Token Scope Substitution | MCP Profile | Token Scope Substitution is the use of a valid token, authorization code, or refresh grant under an audience, resource, or operation-scope context that was not bound to the original authorization. |
| Defense Evasion | [SAF-T1401](techniques/SAF-T1401/README.md) | Line Jumping | MCP Profile | Line Jumping covers an attacker causing an MCP tool, prompt, or resource under attacker influence to win a host, proxy, or registry resolution decision ahead of a trusted competing object. |
| Defense Evasion | [SAF-T1402](techniques/SAF-T1402/README.md) | Instruction Steganography | SAF Core, MCP Profile | Instruction Steganography is the concealment of an adversarial instruction inside a representation whose operational meaning is hidden from an ordinary reviewer but recoverable by an agent or model after the carrier crosses an untrusted-content boundary. |
| Defense Evasion | [SAF-T1403](techniques/SAF-T1403/README.md) | Consent-Fatigue Exploit | MCP Profile | Consent-Fatigue Exploit covers an adversary causing materially equivalent agent or MCP approval requests to recur until a user accepts one, crossing the human authorization boundary that gates a tool call, privilege elevation, or data disclosure. |
| Defense Evasion | [SAF-T1404](techniques/SAF-T1404/README.md) | Response Tampering | MCP Profile | Response Tampering covers modification, substitution, or misrouting after an MCP operation emits a response and before a host, model, or downstream application consumes it as authentic. |
| Defense Evasion | [SAF-T1405](techniques/SAF-T1405/README.md) | Tool Obfuscation/Renaming | MCP Profile | Tool Obfuscation/Renaming covers attacker control of a tool's machine name, human-facing title, or description so that an MCP host, model, operator, or name-based control confuses the tool with an expected capability, prefers it over a competitor, or overlooks a material identity change. |
| Defense Evasion | [SAF-T1406](techniques/SAF-T1406/README.md) | Metadata Manipulation | MCP Profile | Metadata Manipulation covers adversary-controlled changes to MCP or agentic object descriptors that cause a client, host, model, reviewer, policy engine, inventory, or monitor to treat the object as safer, more trusted, or more appropriate than it is. |
| Defense Evasion | [SAF-T1407](techniques/SAF-T1407/README.md) | Server Proxy Masquerade | MCP Profile | Server Proxy Masquerade covers an attacker-controlled MCP endpoint that appears to be an approved server or protected resource while it relays, is positioned to relay, or reuses MCP or OAuth exchanges associated with a legitimate service. |
| Defense Evasion | [SAF-T1408](techniques/SAF-T1408/README.md) | OAuth Protocol Downgrade | MCP Profile | OAuth Protocol Downgrade covers attacker-influenced weakening of PKCE from S256 to plain or from PKCE to no challenge during an HTTP-based MCP authorization flow, when the client or authorization server accepts that weaker state and defeats the intended code binding. |
| Credential Access | [SAF-T1501](techniques/SAF-T1501/README.md) | Full-Schema Poisoning (FSP) | SAF Core, MCP Profile | FSP covers a structurally valid MCP tool definition whose coordinated adversarial semantics occupy at least two model-visible definition paths, including a schema-resident path, and influence tool planning before execution. |
| Credential Access | [SAF-T1502](techniques/SAF-T1502/README.md) | File-Based Credential Harvest | MCP Profile, Code-Agent Profile | This technique covers an MCP or agentic component using filesystem visibility to locate and read a credential-bearing ordinary file, placing its contents into a tool result, model context, or adversary-directed workflow. |
| Credential Access | [SAF-T1503](techniques/SAF-T1503/README.md) | Env-Var Scraping | MCP Profile, Code-Agent Profile | Env-Var Scraping covers a malicious or compromised local stdio MCP server enumerating the variable names and values visible inside its own launched process. |
| Credential Access | [SAF-T1504](techniques/SAF-T1504/README.md) | Token Theft via API Response | MCP Profile | This technique covers an adversary obtaining a reusable access, bearer, refresh, or session token because an MCP tool or agentic API response delivers that token to a recipient not authorized to possess it. |
| Credential Access | [SAF-T1505](techniques/SAF-T1505/README.md) | In-Memory Secret Extraction | SAF Core, MCP Profile, RAG and Memory Profile | In-Memory Secret Extraction is the unauthorized acquisition of authentication material or another secret from live process-wide environment or runtime state held by an MCP host, agent runtime, or server. |
| Credential Access | [SAF-T1506](techniques/SAF-T1506/README.md) | Infrastructure Token Theft | MCP Profile | The technique applies when an MCP, agent, gateway, tool, plugin, or adjacent workload can reach a token-bearing source such as a process environment, projected service-account volume, or cloud metadata service and transfers the resulting credential outside its intended trust boundary. |
| Credential Access | [SAF-T1507](techniques/SAF-T1507/README.md) | Authorization Code Interception | MCP Profile | Authorization Code Interception covers an adversary obtaining an OAuth authorization code from the redirect-to-client path used by an HTTP MCP authorization flow, then redeeming or attempting to redeem it when transaction binding or validation is absent or defeated. |
| Discovery | [SAF-T1601](techniques/SAF-T1601/README.md) | MCP Server Enumeration | MCP Profile | MCP Server Enumeration is the adversarial inventory of the MCP servers available to a compromised or misused host context, using host configuration, connection establishment, or MCP discovery metadata to identify and characterize the server set. |
| Discovery | [SAF-T1602](techniques/SAF-T1602/README.md) | Tool Enumeration | MCP Profile | Tool Enumeration is an actor's use of tools/list, including pagination, to obtain the tool definitions an MCP server makes available to that requesting principal. |
| Discovery | [SAF-T1603](techniques/SAF-T1603/README.md) | System Prompt Disclosure | SAF Core, MCP Profile | This technique covers unauthorized recovery of the whole or a substantial portion of hidden system, developer, or agent instructions across the boundary separating privileged instruction context from an untrusted requester, remote peer, or tool-mediated recipient. |
| Discovery | [SAF-T1604](techniques/SAF-T1604/README.md) | Server Version Enumeration | MCP Profile | SAF-T1604 covers a client collecting implementation or supported-protocol versions from a reached MCP server or its HTTP serving layer. |
| Discovery | [SAF-T1605](techniques/SAF-T1605/README.md) | Capability Mapping | MCP Profile | Capability Mapping covers an adversary using its current MCP request identity to enumerate advertised server features and correlate the returned metadata into a map for follow-on selection. |
| Discovery | [SAF-T1606](techniques/SAF-T1606/README.md) | Directory Listing via File Tool | MCP Profile, Code-Agent Profile | SAF-T1606 covers a model, client, or actor invoking a file-capable MCP tool to obtain names, entry types, sizes, counts, matching paths, or directory structure from the filesystem namespace available to the server. |
| Lateral Movement | [SAF-T1204](techniques/SAF-T1204/README.md) | Context Memory Implant | SAF Core, MCP Profile, RAG and Memory Profile | This technique covers an adversary causing selected content to be written into an agent's persistent context memory so that retrieval in a later session influences reasoning, a response, planning, or a tool decision. |
| Lateral Movement | [SAF-T1701](techniques/SAF-T1701/README.md) | Cross-Tool Contamination | SAF Core, MCP Profile | This technique requires a source-tool result influenced by an adversary, a later call to a distinct tool or server in the same execution context, and a causal link between the untrusted result and that later call. |
| Lateral Movement | [SAF-T1703](techniques/SAF-T1703/README.md) | Tool-Chaining Pivot | SAF Core, MCP Profile | In scope, an upstream tool description, result, retrieved object, or server-supplied instruction influences a later call to a distinct tool, server, connector, application, or security domain; the later call is unsupported by user intent and uses authority already available to the agent. |
| Lateral Movement | [SAF-T1704](techniques/SAF-T1704/README.md) | Compromised-Server Pivot | SAF Core, MCP Profile | This technique begins after the adversary controls the behavior or responses of an MCP server and ends when that influence causes the connected host to cross into a different trust domain with host-held authority. |
| Lateral Movement | [SAF-T1705](techniques/SAF-T1705/README.md) | Cross-Agent Instruction Injection | SAF Core, MCP Profile | Cross-Agent Instruction Injection is the transfer of attacker-authored instructions from an attacker-influenced agent context into a distinct receiving agent, where the receiver treats the peer's output as task content, evidence, or authority and changes behavior or invokes a capability. |
| Lateral Movement | [SAF-T1706](techniques/SAF-T1706/README.md) | OAuth Token Pivot Replay | MCP Profile | This technique covers an adversary presenting a captured OAuth bearer access token from an MCP or agent-connected component to a reachable protected resource, where acceptance moves the adversary across that resource boundary as the token subject. |
| Lateral Movement | [SAF-T1707](techniques/SAF-T1707/README.md) | CSRF Token Relay | MCP Profile | A valid, attacker-obtained state value is accepted from a different browser or session, and the callback completes an attacker-originated authorization flow or misbinds an account. |
| Collection | [SAF-T1801](techniques/SAF-T1801/README.md) | Automated Data Harvesting | SAF Core, MCP Profile | Automated Data Harvesting is the adversarial use of an agentic system to enumerate, retrieve, and aggregate a broader set of data through MCP resources or data-reading tools than the user's bounded task requires. |
| Collection | [SAF-T1802](techniques/SAF-T1802/README.md) | File Collection | MCP Profile, Code-Agent Profile | File Collection covers obtaining file content through an MCP resource or tool, including use of an intended collection capability and retrieval that exceeds the actor's approved path, authorization, or approval boundary. |
| Collection | [SAF-T1803](techniques/SAF-T1803/README.md) | Database Dump | MCP Profile | Database Dump covers an MCP-connected or agentic database capability being directed or abused to create, stream, or assemble a broad reusable copy of database contents beyond the operator's intended task. |
| Collection | [SAF-T1804](techniques/SAF-T1804/README.md) | API Data Harvest | SAF Core, MCP Profile | API Data Harvest covers repeated MCP resource reads or data-query tool calls that enumerate collections or retrieve API- or database-backed records beyond the breadth, fields, rows, or volume justified by the immediate user task. |
| Collection | [SAF-T1805](techniques/SAF-T1805/README.md) | Context Snapshot Capture | SAF Core, MCP Profile, RAG and Memory Profile | Context Snapshot Capture is the unauthorized read, export, or serialization of point-in-time active agent execution state across the state owner's or tenant's authorization boundary. |
| Command and Control | [SAF-T1901](techniques/SAF-T1901/README.md) | Outbound Webhook C2 | SAF Core, MCP Profile | The security boundary is the point where a model-controlled tool or agent scheduler turns invocation context into outbound HTTP traffic and then makes a response available to the agent or downstream automation. |
| Command and Control | [SAF-T1902](techniques/SAF-T1902/README.md) | Response-Borne Covert Channel | SAF Core, MCP Profile | SAF-T1902 covers an adversary concealing control data, collected data, or a callback trigger inside an MCP or agent response so that a cooperating receiver obtains it through response processing, rendering, or relay outside the intended review path. |
| Command and Control | [SAF-T1903](techniques/SAF-T1903/README.md) | Malicious Server Control Channel | MCP Profile | This technique covers a malicious or trojanized MCP server, or a server-adjacent integration presented as one, that uses its execution placement to establish or service a bidirectional operator channel for receiving commands and returning results. |
| Command and Control | [SAF-T1904](techniques/SAF-T1904/README.md) | Chat-Based Backchannel | SAF Core, MCP Profile | Chat-Based Backchannel covers a repeatable bidirectional operator-control path in which an external chat identity or conversation can supply actionable input to a tool-capable agent and receive returned status or results outside the authorized control plane. |
| Exfiltration | [SAF-T1902](techniques/SAF-T1902/README.md) | Response-Borne Covert Channel | SAF Core, MCP Profile | SAF-T1902 covers an adversary concealing control data, collected data, or a callback trigger inside an MCP or agent response so that a cooperating receiver obtains it through response processing, rendering, or relay outside the intended review path. |
| Exfiltration | [SAF-T1910](techniques/SAF-T1910/README.md) | Covert Channel Exfiltration | SAF Core, MCP Profile | Covert Channel Exfiltration covers an adversary causing an MCP-enabled or agentic host to place sensitive context in an apparently legitimate tool argument, application message, URL, or downstream service side effect so that the data crosses to an unintended external party while its disclosure purpose is obscured. |
| Exfiltration | [SAF-T1911](techniques/SAF-T1911/README.md) | Parameter Exfiltration | SAF Core, MCP Profile | Parameter Exfiltration is the unauthorized transmission of sensitive data by placing it in the argument values of an MCP tool call. |
| Exfiltration | [SAF-T1913](techniques/SAF-T1913/README.md) | HTTP POST Exfil | MCP Profile | HTTP POST Exfil is the transfer of sensitive data from an MCP host or client to an adversary-controlled remote MCP server by placing that data in tools/call arguments carried in a Streamable HTTP POST body. |
| Exfiltration | [SAF-T1914](techniques/SAF-T1914/README.md) | Tool-to-Tool Exfil | SAF Core, MCP Profile | Tool-to-Tool Exfil covers an agentic host carrying confidential data returned by one source tool into a distinct outbound-capable sink tool or server under adversary-influenced instructions, causing or attempting unauthorized disclosure. |
| Exfiltration | [SAF-T1915](techniques/SAF-T1915/README.md) | Cross-Chain Laundering via Bridges/DEXs | Financial-Agent Profile | This technique covers an adversary using an agent with delegated financial-tool authority to compose a bridge action and a decentralized-exchange swap into a multi-chain sequence intended to layer illicit proceeds. |
| Impact | [SAF-T2101](techniques/SAF-T2101/README.md) | Data Destruction | MCP Profile | Data Destruction is an adversary-directed MCP or agent action whose immediate objective is deleting stored data or irreversibly corrupting an addressable resource through a tool or delegated service authority. |
| Impact | [SAF-T2102](techniques/SAF-T2102/README.md) | Service Disruption | MCP Profile | The defining boundary is crossed when attacker-controlled activity at an MCP or agent interface causes measurable loss of availability, capacity, or task continuity beyond the attacker's own work. |
| Impact | [SAF-T2103](techniques/SAF-T2103/README.md) | Code Sabotage | SAF Core, MCP Profile, Code-Agent Profile | Code Sabotage is an adversary-directed use of an agentic coding path to make unauthorized, behavior-changing edits to repository source, tests, build logic, or security configuration, with an immediate integrity or availability objective. |
| Impact | [SAF-T2104](techniques/SAF-T2104/README.md) | Fraudulent Transactions | SAF Core, MCP Profile, Financial-Agent Profile | This technique covers an adversary causing a tool-enabled agent to initiate, commit, or materially alter a value-bearing transaction beyond the user's or organization's current authorization. |
| Impact | [SAF-T2105](techniques/SAF-T2105/README.md) | Disinformation Output | SAF Core, MCP Profile | In scope are deliberately misleading generated assertions, fabricated identities or provenance, simulated consensus, and attacker-directed false answers produced through manipulated retrieval context. |
| Impact | [SAF-T2106](techniques/SAF-T2106/README.md) | Context Memory Poisoning via Vector Store Contamination | SAF Core, MCP Profile, RAG and Memory Profile | Context memory poisoning via vector store contamination occurs when an adversary crosses a write or collection-ownership boundary to place attacker-controlled records in persistent retrieval memory, and a later semantically matched retrieval incorporates those records into an agent's context. |
| Impact | [SAF-T3001](techniques/SAF-T3001/README.md) | RAG Backdoor Attack | SAF Core, MCP Profile, RAG and Memory Profile | This technique covers durable corpus insertion, trigger-conditioned retrieval, and downstream generation of the selected response with an unchanged retriever and generator. |

## Deprecated Compatibility IDs

Deprecated IDs remain permanent and navigable for provenance. Use their active replacements for new mappings.

| Deprecated ID | Historical Name | Replacement |
| --- | --- | --- |
| [SAF-T1104](techniques/SAF-T1104/README.md) | Over-Privileged Tool Abuse | [SAF-T1302](techniques/SAF-T1302/README.md) — Agentic Confused Deputy |
| [SAF-T1109](techniques/SAF-T1109/README.md) | Debugging Tool Exploitation | [SAF-T1005](techniques/SAF-T1005/README.md) — Exposed Endpoint Exploit<br>[SAF-T1101](techniques/SAF-T1101/README.md) — Command Injection |
| [SAF-T1205](techniques/SAF-T1205/README.md) | Persistent Tool Redefinition | [SAF-T1201](techniques/SAF-T1201/README.md) — Post-Approval Tool Mutation |
| [SAF-T1301](techniques/SAF-T1301/README.md) | Cross-Server Tool Shadowing | [SAF-T1008](techniques/SAF-T1008/README.md) — Cross-Server Tool Shadowing |
| [SAF-T1306](techniques/SAF-T1306/README.md) | Rogue Authorization Server | [SAF-T1009](techniques/SAF-T1009/README.md) — Authorization Server Mix-up |
| [SAF-T1309](techniques/SAF-T1309/README.md) | Privileged Tool Invocation via Prompt Manipulation | [SAF-T1102](techniques/SAF-T1102/README.md) — Prompt Injection (Multiple Vectors)<br>[SAF-T1302](techniques/SAF-T1302/README.md) — Agentic Confused Deputy |
| [SAF-T1702](techniques/SAF-T1702/README.md) | Shared-Memory Poisoning | [SAF-T1204](techniques/SAF-T1204/README.md) — Context Memory Implant |
| [SAF-T1912](techniques/SAF-T1912/README.md) | Stego Response Exfil | [SAF-T1902](techniques/SAF-T1902/README.md) — Response-Borne Covert Channel |

## Catalog Statistics

- **Tactics**: 14
- **Registered technique IDs**: 86
- **Active techniques**: 78
- **Deprecated compatibility IDs**: 8
- **Active technique-to-tactic mappings**: 82

| Tactic | Active Technique Mappings |
| --- | ---: |
| Reconnaissance | 0 |
| Resource Development | 1 |
| Initial Access | 9 |
| Execution | 8 |
| Persistence | 6 |
| Privilege Escalation | 8 |
| Defense Evasion | 8 |
| Credential Access | 7 |
| Discovery | 6 |
| Lateral Movement | 7 |
| Collection | 5 |
| Command and Control | 4 |
| Exfiltration | 6 |
| Impact | 7 |
<!-- END GENERATED SAF TECHNIQUE CATALOG -->

## Usage Guidelines

- Use technique IDs (e.g., SAF-T1001) for consistent reference across documentation
- Select SAF Core and the domain profiles that match your deployment
- Map active techniques to your specific agentic environment for risk assessment
- Preserve deprecated IDs when consuming historical mappings, but use their listed replacements for new work
- Regular review as new techniques emerge in the rapidly evolving MCP threat landscape

## License

This project uses a multi-license structure based on the type of content:

- **Techniques and general documentation** are licensed under [CC BY 4.0](LICENSE-CC-BY-4.0)
- **Mitigations** (`mitigations/` and `MITIGATIONS.md`): new contributions are licensed under the [Community Specification License 1.0](LICENSE-CSL-1.0); mitigation content contributed on or before 2026-06-10 remains under [CC BY 4.0](LICENSE-CC-BY-4.0) until the original contributors sign off on relicensing or the content is rewritten
- **Code** (scripts, detection rules, and software) is licensed under [Apache 2.0](LICENSE-APACHE-2.0)

See [LICENSE](LICENSE) for full details, [mitigations/SCOPE.md](mitigations/SCOPE.md) for the mitigation specification's scope, and [mitigations/NOTICES.md](mitigations/NOTICES.md) for Community Specification License notices.

## Governance

The mitigations specification is developed as a Community Specification Working Group under the [Community Specification Governance Policy 1.0](GOVERNANCE.md). See [CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute.

---

Copyright © Secure Agentic Framework a Series of LF Projects, LLC

For web site terms of use, trademark policy and other project policies please see https://lfprojects.org.
