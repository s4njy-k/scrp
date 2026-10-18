/**
 * Legally distinct action routes and their eligibility checks (blueprint v4
 * §26; checklist §6). This is an engineering guardrail, NOT legal advice: it
 * blocks drafts that lack the facts, authority, grounds, jurisdiction,
 * recipient and approvals a route needs, and it never sends anything. Every
 * route's legal text must be re-verified at issuance time by competent people.
 */

export type RouteId =
  | 'it_act_69a_blocking' | 'it_act_79_3_b_intimation' | 'registrar_abuse' | 'registry_escalation' | 'hosting_cdn_abuse'
  | 'app_store_complaint' | 'preservation_request' | 'bnss_94_production' | 'financial_fraud_alert' | 'investigation_lead_package';

export type RecipientKind = 'government_nodal' | 'intermediary' | 'registrar' | 'registry' | 'hosting_provider' | 'cdn' | 'app_distributor' | 'record_holder' | 'bank_or_psp' | 'investigating_officer';

/** The six grounds enumerated in IT Act s.69A(1). A 69A request must rest on one of them. */
export const SECTION_69A_GROUNDS = {
  sovereignty_integrity: 'Interest of the sovereignty and integrity of India',
  defence: 'Defence of India',
  security_of_state: 'Security of the State',
  friendly_relations: 'Friendly relations with foreign States',
  public_order: 'Public order',
  preventing_incitement: 'Preventing incitement to the commission of any cognizable offence relating to the above',
} as const;

export interface LegalRoute {
  id: RouteId;
  title: string;
  nature: string;
  recipientKinds: RecipientKind[];
  /** Fields that must be non-empty before submission (beyond the common ones). */
  requiredFields: ('legal_basis' | 'authority_ref' | 'issuing_authority' | 'signatory_name' | 'signatory_designation' | 'jurisdiction' | 'necessity_note' | 'proportionality_note')[];
  requiredRouteFields: string[];
  guardrail: string;
  compulsory: boolean;
  timing_note?: string;
}

export const LEGAL_ROUTES: Record<RouteId, LegalRoute> = {
  it_act_69a_blocking: {
    id: 'it_act_69a_blocking', title: 'Request for blocking under IT Act s.69A (Blocking Rules 2009)',
    nature: 'Statutory blocking, only where one of s.69A\'s prescribed grounds is actually engaged and the Rules\' procedure applies.',
    recipientKinds: ['government_nodal'], compulsory: false,
    requiredFields: ['legal_basis', 'authority_ref', 'issuing_authority', 'signatory_name', 'signatory_designation', 'necessity_note', 'proportionality_note'],
    requiredRouteFields: ['ground_69a', 'public_access_impact'],
    guardrail: 'Not a generic power to block any fraud domain. An agency analyst cannot self-issue a blocking direction; this drafts a request to the competent nodal/designated channel, which decides under the Rules.',
  },
  it_act_79_3_b_intimation: {
    id: 'it_act_79_3_b_intimation', title: 'Reasoned intimation to an intermediary (IT Act s.79(3)(b); IT Rules 2021 r.3(1)(d) as amended)',
    nature: 'Actual knowledge through a court order or a reasoned written intimation from a duly authorised government officer/agency about specific unlawful information.',
    recipientKinds: ['intermediary', 'hosting_provider', 'app_distributor'], compulsory: false,
    requiredFields: ['legal_basis', 'authority_ref', 'issuing_authority', 'signatory_name', 'signatory_designation', 'jurisdiction'],
    requiredRouteFields: ['unlawful_act_and_provision', 'authorisation_of_officer', 'current_rules_verified'],
    guardrail: 'An ordinary analyst email or abuse report is NOT a statutory s.79 notice. Verify the signatory\'s authorisation and rank, any approved channel (e.g. SAHYOG where institutionally authorised) and the rule text in force at issuance.',
    timing_note: 'The rule text updated 10 February 2026 sets a removal period for intermediaries after qualifying actual knowledge. That is the intermediary\'s legal response period, not an internal SLA, and it runs only from documented receipt.',
  },
  registrar_abuse: {
    id: 'registrar_abuse', title: 'Registrar abuse complaint',
    nature: 'Contractual registration/anti-abuse policy breach (or an applicable order) reported to the sponsoring registrar.',
    recipientKinds: ['registrar'], compulsory: false, requiredFields: ['legal_basis'], requiredRouteFields: ['policy_clause'],
    guardrail: 'A complaint, not an order: request precise, proportionate mitigation and attach the evidence; the registrar applies its own policy.',
  },
  registry_escalation: {
    id: 'registry_escalation', title: 'Registry escalation',
    nature: 'Escalation to the registry operator under its documented policy when the registrar route is exhausted or inappropriate.',
    recipientKinds: ['registry'], compulsory: false, requiredFields: ['legal_basis'], requiredRouteFields: ['policy_clause', 'registrar_contact_history'],
    guardrail: 'Do not treat the registry (e.g. NIXI for .IN) as the registrar for every domain, or demand suspension without grounds or competent approval.',
  },
  hosting_cdn_abuse: {
    id: 'hosting_cdn_abuse', title: 'Hosting / CDN abuse complaint',
    nature: 'Acceptable-use or intermediary policy complaint to the hosting provider, or to a CDN\'s abuse channel where applicable.',
    recipientKinds: ['hosting_provider', 'cdn'], compulsory: false, requiredFields: ['legal_basis'], requiredRouteFields: ['ip_observation_note'],
    guardrail: 'A CDN is often a proxy, not the content owner or registrar; edge-IP blocking can affect unrelated customers. Qualify IP/ASN data as observed from this vantage.',
  },
  app_store_complaint: {
    id: 'app_store_complaint', title: 'App store / distributor complaint',
    nature: 'Store impersonation/malware/fraud policy complaint, or an official legal process, to the distributor.',
    recipientKinds: ['app_distributor'], compulsory: false, requiredFields: ['legal_basis'], requiredRouteFields: ['store_listing_or_package'],
    guardrail: 'Never state a signing fingerprint unless the APK bytes were actually collected and analysed; a web link is not proof of store distribution.',
  },
  preservation_request: {
    id: 'preservation_request', title: 'Voluntary data preservation request',
    nature: 'Request that a record holder preserve specified data pending lawful process; voluntary where no statutory power is invoked.',
    recipientKinds: ['record_holder', 'registrar', 'hosting_provider', 'bank_or_psp', 'intermediary'], compulsory: false,
    requiredFields: ['legal_basis', 'issuing_authority'], requiredRouteFields: ['data_categories', 'time_window'],
    guardrail: 'Keep preservation distinct from production. Do not word a voluntary request as a compulsory demand.',
  },
  bnss_94_production: {
    id: 'bnss_94_production', title: 'Production of documents/records (BNSS s.94)',
    nature: 'Lawful production process, as appropriate to the issuer, proceedings and jurisdiction.',
    recipientKinds: ['record_holder', 'registrar', 'hosting_provider', 'bank_or_psp', 'intermediary'], compulsory: true,
    requiredFields: ['legal_basis', 'authority_ref', 'issuing_authority', 'signatory_name', 'signatory_designation', 'jurisdiction', 'necessity_note'],
    requiredRouteFields: ['data_categories', 'time_window', 'proceeding_reference', 'cross_border'],
    guardrail: 'The platform never issues compulsory demands. Only a competent officer may sign. Holders outside India may require MLAT or other lawful channels.',
  },
  financial_fraud_alert: {
    id: 'financial_fraud_alert', title: 'Financial-fraud alert / freezing lead',
    nature: 'Lead to a bank/PSP/NPCI/CFCFRMS workflow as permitted, or urgent escalation to competent authorities.',
    recipientKinds: ['bank_or_psp', 'government_nodal'], compulsory: false, requiredFields: ['authority_ref'], requiredRouteFields: ['masked_identifiers', 'urgency'],
    guardrail: 'A lead is not a freeze order. An analyst-generated sheet cannot itself direct a debit freeze.',
  },
  investigation_lead_package: {
    id: 'investigation_lead_package', title: 'Investigation lead package',
    nature: 'Intelligence sharing with the concerned investigating officer/agency under current I4C/State LEA rules.',
    recipientKinds: ['investigating_officer'], compulsory: false, requiredFields: [], requiredRouteFields: ['evidentiary_weaknesses', 'next_steps'],
    guardrail: 'Do not disclose unrelated citizens\' identifiers or unsupported attribution; state weaknesses and confidence explicitly.',
  },
};

export interface EligibilityCheck {
  code: string;
  ok: boolean;
  blocking: boolean;
  message: string;
}

export interface EligibilityInput {
  route: RouteId;
  fields: Record<string, unknown>;
  routeFields: Record<string, unknown>;
  recipientKind: string | null;
  targets: { target_id: number; url: string; verdict: string | null; suppressed: boolean; evidence_attempts: string[]; evidence_ok: boolean; has_app_link: boolean }[];
  creatorId: string | null;
  actorId: string | null;
  stage: 'submit' | 'approve' | 'generate';
}

const present = (v: unknown) => (typeof v === 'string' ? v.trim().length > 0 : Array.isArray(v) ? v.length > 0 : v !== undefined && v !== null && v !== false);

/** Evaluate every check; blocking failures stop the transition and are returned to the user verbatim. */
export function checkEligibility(i: EligibilityInput): EligibilityCheck[] {
  const r = LEGAL_ROUTES[i.route];
  const out: EligibilityCheck[] = [];
  const add = (code: string, ok: boolean, message: string, blocking = true) => out.push({ code, ok, blocking, message });
  add('targets_present', i.targets.length > 0, 'At least one specific URL/domain is required.');
  add('recipient_kind', i.recipientKind !== null && r.recipientKinds.includes(i.recipientKind as RecipientKind),
    `Recipient must be one of: ${r.recipientKinds.join(', ')} (got ${i.recipientKind ?? 'none'}).`);
  add('facts_summary', present(i.fields.facts_summary), 'A factual summary (observations, not unproven allegations) is required.');
  add('requested_action', present(i.fields.requested_action), 'A precise, bounded requested action is required.');
  for (const f of r.requiredFields) add(`field_${f}`, present(i.fields[f]), `${f.replace(/_/g, ' ')} is required for this route.`);
  for (const f of r.requiredRouteFields) add(`route_${f}`, present(i.routeFields[f]), `${f.replace(/_/g, ' ')} is required for this route.`);
  if (i.route === 'it_act_69a_blocking') {
    const g = String(i.routeFields.ground_69a ?? '');
    add('ground_69a_valid', g in SECTION_69A_GROUNDS, `A s.69A request must rest on a prescribed ground: ${Object.keys(SECTION_69A_GROUNDS).join(', ')}. Ordinary fraud alone may not engage s.69A.`);
  }
  if (i.route === 'it_act_79_3_b_intimation') add('rules_verified', i.routeFields.current_rules_verified === true, 'Confirm the IT Rules text in force at issuance has been verified.');
  if (i.route === 'bnss_94_production' && i.routeFields.cross_border === true) {
    add('cross_border_channel', present(i.routeFields.lawful_channel_note), 'Holders outside India: record the lawful channel (e.g. MLAT/letter rogatory) before proceeding.');
  }
  if (i.route === 'app_store_complaint') add('app_evidence', i.targets.every((t) => t.has_app_link) || present(i.routeFields.store_listing_or_package), 'Each target needs an observed store link/package, or the listing must be identified.');
  for (const t of i.targets) {
    add(`target_${t.target_id}_not_suppressed`, !t.suppressed, `${t.url}: marked false positive/benign by an analyst; external action is blocked unless an approver overrides on new evidence.`);
    add(`target_${t.target_id}_reviewed`, t.verdict === 'suspicious' || t.verdict === 'likely_malicious', `${t.url}: needs an analyst verdict of suspicious or likely malicious (current: ${t.verdict ?? 'unreviewed'}).`);
    add(`target_${t.target_id}_evidence`, t.evidence_attempts.length > 0 && t.evidence_ok, `${t.url}: cite at least one committed capture whose artifacts verify.`);
  }
  if (i.stage === 'approve' || i.stage === 'generate') {
    add('maker_checker', Boolean(i.creatorId && i.actorId && i.creatorId !== i.actorId), 'The approver must be a different person from the author (maker-checker).');
  }
  add('no_autosend', true, 'This system never sends notices: issuance is an authorised human act recorded afterwards with proof.', false);
  return out;
}

export const blockingFailures = (checks: EligibilityCheck[]) => checks.filter((c) => c.blocking && !c.ok);
