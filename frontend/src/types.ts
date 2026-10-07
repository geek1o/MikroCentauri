export interface Endpoint {
  ID: string;
  Name: string;
  Protocol: string;
  Server: string;
  Port: number;
  enabled?: boolean;
  Enabled?: boolean;
}
export interface Group {
  id: string;
  type: string;
  members: string[];
  selected?: string;
  interval?: string;
  tolerance?: number;
}
export interface Rule {
  id: string;
  name?: string;
  enabled?: boolean;
  priority?: number;
  source_cidrs?: string[];
  domains?: string[];
  suffixes?: string[];
  destination_cidrs?: string[];
  rule_sets?: string[];
  services?: string[];
  ports?: number[];
  network?: string;
  outbound: string;
}
export interface Policy {
  rules: Rule[];
  services: any[];
  source_direct: string[];
  source_proxy: { cidrs: string[]; outbound: string }[];
  default_outbound: string;
  dns: {
    bootstrap: string;
    fakeip_range: string;
    selected_domains: string[];
    selected_suffixes: string[];
  };
  rule_sets: { id: string; format: string }[];
}
export interface Config {
  revision?: number;
  draft_revision?: number;
  base_revision?: number;
  model: {
    instance: string;
    mode: string;
    endpoints: Endpoint[];
    wireguard: any[];
    groups: Group[];
    rule_count: number;
  };
  policy: Policy;
}
