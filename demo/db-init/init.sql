CREATE TABLE IF NOT EXISTS items (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    status VARCHAR(50)
);

INSERT INTO items (name, status) VALUES
('Auth', 'Online');

CREATE TABLE IF NOT EXISTS team_owners (
    team_id VARCHAR(32) PRIMARY KEY,
    team_name VARCHAR(128) NOT NULL,
    responsibility_scope VARCHAR(255) NOT NULL,
    email VARCHAR(128) NOT NULL,
    slack_channel VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS tracked_endpoints (
    id SERIAL PRIMARY KEY,
    endpoint_name VARCHAR(255) NOT NULL,
    protocol VARCHAR(32) NOT NULL,
    port INTEGER NOT NULL,
    owner_team_id VARCHAR(32) NOT NULL REFERENCES team_owners(team_id),
    environment VARCHAR(64),
    notes TEXT
);

CREATE TABLE IF NOT EXISTS certificate_inventory (
    id SERIAL PRIMARY KEY,
    endpoint_id INTEGER NOT NULL REFERENCES tracked_endpoints(id) ON DELETE CASCADE,
    cert_issuer VARCHAR(255),
    cert_subject VARCHAR(255),
    serial_number VARCHAR(128),
    not_before TIMESTAMP,
    not_after TIMESTAMP,
    key_algorithm VARCHAR(64),
    key_size INTEGER,
    auto_renew BOOLEAN DEFAULT FALSE,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS cmdb_services (
    ci_id VARCHAR(64) PRIMARY KEY,
    entity_ref VARCHAR(255) NOT NULL,
    service_name VARCHAR(255) NOT NULL,
    declared_exposure_tier VARCHAR(32),
    observed_exposure_tier VARCHAR(32),
    declared_replicas INTEGER,
    observed_replicas INTEGER,
    declared_image_digest VARCHAR(255),
    observed_image_digest VARCHAR(255),
    drift_status VARCHAR(32),
    last_reconciled_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cmdb_component_nodes (
    component_id VARCHAR(64) PRIMARY KEY,
    ci_id VARCHAR(64) NOT NULL REFERENCES cmdb_services(ci_id) ON DELETE CASCADE,
    domain VARCHAR(128),
    layer_id VARCHAR(64),
    category_type VARCHAR(64),
    owner_team_id VARCHAR(32) REFERENCES team_owners(team_id),
    name VARCHAR(255),
    version_or_identifier VARCHAR(128),
    status VARCHAR(32),
    notes TEXT
);

CREATE TABLE IF NOT EXISTS software_version_crosswalk (
    component_id VARCHAR(64) PRIMARY KEY REFERENCES cmdb_component_nodes(component_id) ON DELETE CASCADE,
    purl VARCHAR(512),
    cpe23_uri VARCHAR(255),
    eol_product_slug VARCHAR(128),
    eol_cycle_key VARCHAR(128),
    eol_cycle_strategy VARCHAR(64),
    eol_api_url VARCHAR(512),
    vendor_lifecycle_stream VARCHAR(128),
    osv_ecosystem VARCHAR(64),
    osv_package_name VARCHAR(255),
    nvd_cpe_match_string VARCHAR(255),
    ghsa_ecosystem VARCHAR(64),
    distro_advisory_namespace VARCHAR(128),
    semver_sort_tuple INT[]
);

CREATE TABLE IF NOT EXISTS public_eol_cycles (
    eol_product_slug VARCHAR(128) NOT NULL,
    cycle VARCHAR(64) NOT NULL,
    is_lts BOOLEAN DEFAULT FALSE,
    release_date DATE,
    active_support_end_date DATE,
    eol_date DATE,
    latest_patch_version VARCHAR(64),
    PRIMARY KEY (eol_product_slug, cycle)
);

CREATE TABLE IF NOT EXISTS public_cve_ranges (
    cve_id VARCHAR(32) PRIMARY KEY,
    eol_product_slug VARCHAR(128),
    distro_advisory_namespace VARCHAR(128),
    introduced_version VARCHAR(64),
    fixed_version VARCHAR(64),
    cvss_v3_score NUMERIC(3,1),
    epss_score NUMERIC(5,4),
    is_cisa_kev BOOLEAN DEFAULT FALSE,
    advisory_source VARCHAR(128)
);

INSERT INTO team_owners (team_id, team_name, responsibility_scope, email, slack_channel)
VALUES
    ('sre-team', 'SRE Team', 'Infrastructure and reliability', 'sre@example.com', '#sre-team'),
    ('app-team', 'App Team', 'Application development and operations', 'app@example.com', '#app-team')
ON CONFLICT (team_id) DO NOTHING;
