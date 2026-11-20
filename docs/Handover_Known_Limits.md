# Known limits at handover

What the three agents do not do yet, with the measured numbers behind each point. We put this next to the deliverable so that you
hear it from us first. Numbers come from the result files in `docs/research/` and from the runs described here.

## 1. Threat quality: a cited pattern is a reference, not a verified fit

* The automatic checks on a generated threat (citation present and real, fields complete, STRIDE wording consistent, claim grounded in the retrieved entry) were passed at the first attempt by 38% of cards (9 of 24) before our latest change and by 96% and 100% (23 and 24 of 24) after it, on a local model (llama3.1:8b).
* **These checks do not measure whether the pattern fits the asset.** One reviewer, not a security expert, read all 24 cards of one run. Of the 22 that passed the checks, none fit their cited pattern well, 8 fit loosely and 14 did not fit (for example a hardware "lock bit" pattern cited for a door-lock key). The most common cause is that the model writes "firmware" or "lock" into the attack for assets that are keys, permission records or images.
* Searching the knowledge base again with the model's attack sentence was better for 5 of 21 comparable cards, the same for 14 and worse for 2, and no similarity floor separated good matches from bad ones. We did not adopt it.
* **What this means for you:** treat the cited catalogue pattern as a pointer that a reviewer has to confirm, and do not use it as evidence that a threat is right.

## 2. The automatic checker makes mistakes

On 50 labelled scenarios the validator wrongly accepted 4 of 26 invalid ones (15.38%). It wrongly rejected 2 of 24 valid ones (8.33%) until we widened its vocabulary; the 0% rate now measured was tuned on the same 50 cases and is not independent evidence. The human approval is the safeguard.

## 3. Retrieval from the public catalogues is weak

With the full catalogue (2,300 entries) precision at 5 on our 40 labelled pairs is 0.17 against 0.57 for a small hand-written set, and only 1 of the six reference threats of the requirements document was matched. The reference threats come from internal patterns that public catalogues do not contain.

## 4. Risk ratings

* Impact and attack feasibility are suggested by the model, then computed by fixed rules. No expert has rated real threats.
* With the new prompt the feasibility of 13 threats varies (Low, Medium, High) and risk varies (Medium, High). Impact is still nearly uniform (operational impact "Major" on 11 to 12 of 13). Agreement with the six reference risks is 5 of 18 exact matches, no better than before, because the earlier "everything High" matched three of them by chance.
* Residual risk is the expert's judgement; there is no control-effectiveness model.

## 5. Compliance mapping

* The rules CR-1 to CR-5 and the resistance classes are Team 2's own version 1.
* **Checked on 2026-11-20:** the attacker class to AVA_VAN component mapping, and the EAL column, against the Common Criteria text in our knowledge base (CEM:2022 R1 Table B.3 and CC:2022 R1 Part 5). They agree: EAL2 contains AVA_VAN.2, EAL4 AVA_VAN.3, EAL5 AVA_VAN.4 and EAL6 AVA_VAN.5, so "EAL2+", "EAL4+" and "EAL5+" are valid augmentations (EAL5 and EAL6 would be the natural levels for AVA_VAN.4 and AVA_VAN.5). An EAL contains more than the vulnerability analysis; the table maps that one requirement.
* **Not verified: the SESIP levels.** The SESIP methodology (GlobalPlatform GP_FST_070, v1.2 of July 2023) could not be read, because its free copy is behind a download button. A secondary GlobalPlatform presentation ties SESIP 3 to Enhanced-Basic, SESIP 4 to Moderate and SESIP 5 to High attack resistance. Our table gives SESIP 2, 3 and 4 for those classes, so the SESIP column may be one level too low for them. Treat it as provisional. The JIL and CC passages are cited on each record; SESIP carries no citation.
* The written rationale is checked for the levels it names and the passages it cites, not for meaning. In the three-use-case run 9 of 13 records got a rationale; the others kept the rule-based justification.

## 6. The sample data is demo data

Asset ratings and damage scenarios were entered by an AI reviewer following the project's example answers. Risk and compliance decisions were scripted, and Team 1's approvals are recorded as unverified. Named-user approvals work (a viewer and an analyst are refused, and the approver's verified name is recorded even if another name is typed), but they were only tested, not used by a real reviewer.

## 7. Coverage

Some assets end with no approved threat because every card for them was discarded (6, 4 and 2 assets in UC-01, UC-02 and UC-03 of the sample run). The export lists the threats that exist; there is not yet a per-asset list that says why an asset has none.

## 8. Operations

* The shared state is one JSON file with a lock, which suits one machine. Several machines need a database store.
* API keys are per user with roles. There is no single sign-on and no key expiry.
* No independent security review or certification has been done.

## 9. Upstream data (Team 1)

Most data flows carry no protocol, so imported assets have no interface (the importer says so). Their modelling step sometimes produced duplicate flows and open payload questions; the importer lists a duplicate flow once. Storing our results in their database is not wired.

## 10. Models

Tested with a local llama3.1:8b (RTX 4060, about 4 s per call) and a hosted gpt-4o-mini. A local model varies from run to run; qwen3.5:9b was about twice as slow with no better result. A model of 8 billion parameters is enough for a demonstration and is not shown to be enough for production.
