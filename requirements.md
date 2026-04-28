Functional requirements
FR1 – Data Submission  
The system must allow clients to submit data entries to the Bulletin Board.

FR2 – Data Publication  
All submitted entries must be made publicly available through the Bulletin Board interface.

FR3 – Inclusion Verification  
The system must provide a mechanism for clients to verify that a submitted entry has been included in the log.

FR4 – Verifiable Receipt Generation  
After submission, the system must provide the client with a receipt that enables later verification of inclusion.

FR5 – Retrieval of Entries  
Clients must be able to retrieve previously published entries.

FR6 – Log State Access  
The current authenticated state of the log must be accessible to all clients.

FR7 – Complaint / Audit Mechanism  
The system must provide a mechanism for clients to report errors, inconsistencies, or suspected attacks.

FR8 – Deterministic Ordering  
The system must define a total and deterministic order over all log entries.


Security requirements
SR1 – Append-Only Security  
It must be computationally infeasible for an adversary to modify or delete previously published entries without being detected.

SR2 – Tamper Detection  
It must be computationally infeasible for an adversary to produce two inconsistent views of the log without detection by clients.

SR3 – Verifiable Inclusion  
It must be computationally infeasible for an adversary to convince a client that an entry is included in the log when it is not.

SR4 – Verifiable Consistency  
It must be computationally infeasible for an adversary to present two log states as consistent if one is not an append-only extension of the other.

SR5 – Integrity of Log Data  
It must be computationally infeasible to forge valid log entries or log states without knowledge of the required cryptographic secrets.

SR6 – Ordering Integrity  
It must be computationally infeasible for an adversary to assign the same position or identifier to two different entries or to produce inconsistent orderings of the log without detection.

SR7 – Non-Equivocation  
It must be computationally infeasible for the log to present different views of the log to different clients without detection.

SR8 – Accountability / Auditability  
If the log deviates from the protocol, it must be possible to produce publicly verifiable evidence of such misbehavior.

