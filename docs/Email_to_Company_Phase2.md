# Draft email to the Infineon mentors (not sent)

**To:** Infineon mentors (Munjuluri Bala Nagendra Raja and team)  **Cc:** Dr. Vidya Gaikwad
**Subject:** TY-A9 Threat/Risk/Compliance agents: thank you, progress, and 7 questions that block the final numbers

Dear all,

Thank you for the review on 12 October. Your feedback is built into our work. In short:

* **Threat Agent:** yes/no security properties, several use cases per product (one result set per use case), going back
  one step when upstream data changes (out-of-date threats are detected and only the affected assets are re-run), STRIDE only,
  and one shared smart-door-lock example for all three teams.
* **Risk Agent (new):** impact on the four axes, attack feasibility from the five ISO/SAE 21434 factors, risk, ranking per asset,
  your treatment options (Reduce / Share / Retain / Avoid), residual risk, and a written justification for every score.
* **Attack-resistance mapping (new):** required attacker resistance with JIL attack potential, SESIP level and CC EAL, as a
  rule base.
* **Human in the loop everywhere:** the expert can accept, edit, reject with a reason (the suggestion is regenerated), adjust
  the risk with a reason, and confirm or override the resistance. Every decision is logged with the person's name, and
  nothing reaches the shared state without an approver.

All of this runs today with **placeholder rating tables**. Every result says which values are yours, which are derived from
yours, and which are our provisional choice. To replace the placeholders we need your numbers:

1. **Overall impact.** In section 2.6, rows T4 (`-/Neg/Mod/Sev` → Moderate) and T5 (`-/Mod/Sev/-` → Moderate) show a lower
   overall impact than their highest axis, while T1, T2, T3 and T6 show the highest axis. Which rule forms the overall impact?
2. **Risk matrix.** You gave 4 of the 12 impact × feasibility cells. Please send the full matrix (we use Negligible, Moderate,
   Major, Severe × Low, Medium, High).
3. **Feasibility points.** Please confirm the point value of each level of the five factors (elapsed time, expertise, knowledge,
   window of opportunity, equipment) and the thresholds for Low, Medium and High. We used an ISO/SAE 21434 Annex G style table.
4. **Impact levels.** What do Negligible, Moderate, Major and Severe mean per axis (safety, financial, operational, privacy)?
5. **Attack resistance.** T1 and T3 have the same risk (High, Medium feasibility) but different required resistance
   (Enhanced-Basic and Moderate). What decides the attacker class? Please also send SESIP and EAL values for the Basic and High
   classes.
6. **Scope.** Section 2.7 lists T1, T3 and T6 only. Do you want a resistance level for every threat we decide to reduce?
7. **Earlier open points:** T6 cites CAPEC-189, but CAPEC-622 (electromagnetic side-channel) looks closer; and whether you can
   share your internal threat patterns or expert judgements (the public MITRE catalogues cover only part of your six reference
   threats: we match 1 of 6 at our similarity threshold).

We will keep the placeholders clearly marked until we hear from you. A short demo (about 8 minutes) can be shown at the next
meeting.

Kind regards,
Team 2, group TY-A9, VIT Pune
