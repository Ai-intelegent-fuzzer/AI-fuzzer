import { useEffect, useState } from 'react';
import { Play, RefreshCw, ShieldCheck } from 'lucide-react';
import { SectionCard } from '../components/common/SectionCard';
import { apiClient } from '../services/api';
import type {
  ApiAttackCategory,
  ApiMemoryRecord,
  ApiRagDocument,
  ApiScenarioResult,
  ApiSyntheticIdentity,
  ApiSyntheticIntegration,
  ApiSyntheticResource,
  ApiToolDefinition,
  ApiMcpResource,
  ApiMcpServer,
  ApiVectorCollection,
  ApiVectorSearchResult,
  ApiWebFixture,
  ApiWebTestCase,
  ApiWebTestRun,
  Target,
} from '../types';

const authorizationScenarios = [
  'horizontal_privilege_escalation',
  'vertical_privilege_escalation',
  'cross_tenant_access',
  'missing_object_authorization',
  'invalid_identity',
  'invalid_session',
  'role_confusion',
  'permission_mismatch',
  'model_instruction_bypass',
  'identity_context_mismatch',
];

const ragScenarios = [
  'unauthorized_document_retrieval',
  'cross_tenant_document_access',
  'indirect_prompt_injection',
  'malicious_document_instructions',
  'retrieval_poisoning',
  'unauthorized_sensitive_disclosure',
  'document_permission_bypass',
  'identity_mismatch',
  'retrieval_context_manipulation',
  'synthetic_canary_exposure',
];

const toolScenarios = [
  'unauthorized_tool_invocation',
  'privilege_escalation_through_tool',
  'cross_tenant_tool_access',
  'tool_argument_manipulation',
  'tool_schema_confusion',
  'tool_description_prompt_injection',
  'malicious_tool_output',
  'indirect_prompt_injection_tool_result',
  'unauthorized_destructive_operation',
  'sensitive_data_exposure',
  'tool_chaining_abuse',
  'tool_identity_mismatch',
  'mcp_resource_access_bypass',
  'mcp_server_trust_violation',
  'simulated_exfiltration_attempt',
];

const integrationScenarios = [
  'excessive_connector_permissions',
  'unauthorized_connector_data_access',
  'cross_tenant_connector_exposure',
  'connector_identity_confusion',
  'synthetic_token_scope_mismatch',
  'integration_data_leakage',
  'connector_prompt_injection',
  'unsafe_connector_write',
  'connector_trust_boundary_violation',
  'insecure_integration_configuration',
  'unauthorized_connector_chaining',
  'connector_sensitive_information_exposure',
  'connector_output_manipulation',
  'missing_connector_authorization',
];

type LabData = {
  targets: Target[];
  identities: ApiSyntheticIdentity[];
  resources: ApiSyntheticResource[];
  documents: ApiRagDocument[];
  tools: ApiToolDefinition[];
  mcpServers: ApiMcpServer[];
  mcpResources: ApiMcpResource[];
  integrations: ApiSyntheticIntegration[];
  vectorCollections: ApiVectorCollection[];
  webFixtures: ApiWebFixture[];
  webTests: ApiWebTestCase[];
};

type TestKind = 'authorization' | 'rag' | 'tools' | 'integrations';

function pretty(value: string) {
  return value.replace(/_/g, ' ');
}

function ScenarioControl({
  title,
  scenarios,
  selected,
  onSelect,
  onRun,
  running,
  result,
}: {
  title: string;
  scenarios: string[];
  selected: string;
  onSelect: (value: string) => void;
  onRun: () => void;
  running: boolean;
  result?: ApiScenarioResult;
}) {
  return (
    <div className="lab-scenario">
      <label className="field-group">
        <span>{title}</span>
        <select value={selected} onChange={(event) => onSelect(event.target.value)}>
          {scenarios.map((scenario) => (
            <option key={scenario} value={scenario}>{pretty(scenario)}</option>
          ))}
        </select>
      </label>
      <button type="button" className="secondary-button" onClick={onRun} disabled={running}>
        <Play size={14} />{running ? 'Running…' : 'Run synthetic test'}
      </button>
      {result ? (
        <div className={`inline-message ${result.outcome === 'vulnerability_detected' ? 'inline-message--warning' : 'inline-message--success'}`} role="status">
          <strong>{pretty(result.outcome ?? result.actual_authorization ?? 'Result recorded')}</strong>
          {result.reason ? <span>{result.reason}</span> : null}
          {result.expected_authorization && result.actual_authorization ? (
            <span>Expected: {pretty(result.expected_authorization)} · Actual: {pretty(result.actual_authorization)}</span>
          ) : null}
          {result.expected_authorization_result && result.actual_authorization_result ? (
            <span>Expected: {pretty(result.expected_authorization_result)} · Actual: {pretty(result.actual_authorization_result)}</span>
          ) : null}
          {typeof result.executed === 'boolean' ? <span>Controlled action executed: {result.executed ? 'yes' : 'no'}</span> : null}
          {result.audit_id ? <span>Audit: <code>{result.audit_id}</code></span> : null}
        </div>
      ) : null}
    </div>
  );
}

export function SecurityLabPage() {
  const [data, setData] = useState<LabData | null>(null);
  const [categories, setCategories] = useState<ApiAttackCategory[]>([]);
  const [targetId, setTargetId] = useState('');
  const [identityId, setIdentityId] = useState('');
  const [selectedScenarios, setSelectedScenarios] = useState<Record<TestKind, string>>({
    authorization: authorizationScenarios[0],
    rag: ragScenarios[0],
    tools: toolScenarios[0],
    integrations: integrationScenarios[0],
  });
  const [results, setResults] = useState<Partial<Record<TestKind, ApiScenarioResult>>>({});
  const [memoryRecords, setMemoryRecords] = useState<ApiMemoryRecord[]>([]);
  const [vectorResults, setVectorResults] = useState<ApiVectorSearchResult[]>([]);
  const [vectorQuery, setVectorQuery] = useState('');
  const [webFixtureId, setWebFixtureId] = useState('');
  const [webTestId, setWebTestId] = useState('');
  const [webRun, setWebRun] = useState<ApiWebTestRun | null>(null);
  const [auxiliaryRunning, setAuxiliaryRunning] = useState(false);
  const [running, setRunning] = useState<TestKind | ''>('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    Promise.all([
      apiClient.getTargets(),
      apiClient.getSyntheticIdentities(),
      apiClient.getSyntheticResources(),
      apiClient.getRagDocuments(),
      apiClient.getSyntheticTools(),
      apiClient.getMcpServers(),
      apiClient.getMcpResources(),
      apiClient.getSyntheticIntegrations(),
      apiClient.getVectorCollections(),
      apiClient.getWebSecurityFixtures(),
      apiClient.getWebSecurityTests(),
    ]).then(async ([targets, identities, resources, documents, tools, mcpServers, mcpResources, integrations, vectorCollections, webFixtures, webTests]) => {
      if (!active) return;
      const selectedTargetId = targets[0]?.targetId ?? '';
      setData({ targets, identities, resources, documents, tools, mcpServers, mcpResources, integrations, vectorCollections, webFixtures, webTests });
      setTargetId(selectedTargetId);
      const defaultIdentity = identities.find((identity) => identity.identity_id === 'synthetic-user-a') ?? identities[0];
      setIdentityId(defaultIdentity?.identity_id ?? '');
      setWebFixtureId(webFixtures[0]?.fixture_id ?? '');
      setWebTestId(webTests[0]?.test_id ?? '');
      setCategories(await apiClient.getAttackCategories(selectedTargetId || undefined));
    }).catch((cause: unknown) => {
      if (active) setError(cause instanceof Error ? cause.message : 'Unable to load synthetic security fixtures.');
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  const selectTarget = async (id: string) => {
    setTargetId(id);
    setError('');
    try {
      setCategories(await apiClient.getAttackCategories(id));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to load target-specific attack categories.');
    }
  };

  const runScenario = async (kind: TestKind) => {
    if (!data) return;
    setRunning(kind);
    setError('');
    try {
      const scenario = selectedScenarios[kind];
      const identity = data.identities.find((item) => item.identity_id === identityId);
      let result: ApiScenarioResult;
      if (kind === 'authorization') {
        result = await apiClient.runAuthorizationScenario(scenario);
      } else if (kind === 'rag') {
        result = await apiClient.runRagScenario(scenario);
      } else if (kind === 'tools') {
        if (!identity) throw new Error('Select a synthetic identity first.');
        result = await apiClient.runToolSecurityTest(scenario, identity);
      } else {
        if (!identity) throw new Error('Select a synthetic identity first.');
        result = await apiClient.runIntegrationSecurityTest(scenario, identity);
      }
      setResults((current) => ({ ...current, [kind]: result }));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to run the synthetic security test.');
    } finally {
      setRunning('');
    }
  };

  const updateScenario = (kind: TestKind, value: string) => {
    setSelectedScenarios((current) => ({ ...current, [kind]: value }));
  };

  const inspectMemory = async () => {
    const identity = data?.identities.find((item) => item.identity_id === identityId);
    if (!identity) return;
    setAuxiliaryRunning(true);
    setError('');
    try {
      setMemoryRecords(await apiClient.getSyntheticMemories(identity));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to inspect synthetic memory.');
    } finally {
      setAuxiliaryRunning(false);
    }
  };

  const searchVectors = async () => {
    const identity = data?.identities.find((item) => item.identity_id === identityId);
    const collection = data?.vectorCollections[0];
    if (!identity || !collection || !vectorQuery.trim()) return;
    setAuxiliaryRunning(true);
    setError('');
    try {
      const response = await apiClient.searchVectorDocuments({
        identity_id: identity.identity_id,
        session_id: identity.session_id,
        query: vectorQuery.trim(),
        collection_id: collection.collection_id,
      });
      setVectorResults(response.results);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to search the local vector fixture.');
    } finally {
      setAuxiliaryRunning(false);
    }
  };

  const runWebFixture = async () => {
    if (!webFixtureId || !webTestId) return;
    setAuxiliaryRunning(true);
    setError('');
    try {
      setWebRun(await apiClient.runWebSecurityTests(webFixtureId, [webTestId]));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to run the local web security fixture.');
    } finally {
      setAuxiliaryRunning(false);
    }
  };

  if (loading) return <div className="page-loading">Loading local security fixtures…</div>;
  if (!data) return <div className="inline-message inline-message--error" role="alert">{error || 'Synthetic fixture data is unavailable.'}</div>;

  return (
    <div className="content-stack">
      <SectionCard
        title="Application security lab"
        subtitle="Inspect and test local synthetic identities, resources, documents, tools and connectors. Scenario runs do not contact external providers."
        action={(
          <button type="button" className="secondary-button" onClick={() => window.location.reload()}>
            <RefreshCw size={14} />Refresh fixtures
          </button>
        )}
      >
        {error ? <div className="inline-message inline-message--error" role="alert">{error}</div> : null}
        <div className="inline-message inline-message--success">
          <ShieldCheck size={16} /><span>Controlled synthetic data only · no real credentials or resources</span>
        </div>
        <label className="field-group">
          <span>Target-specific attack applicability</span>
          <select value={targetId} onChange={(event) => void selectTarget(event.target.value)}>
            {data.targets.map((target) => <option key={target.targetId} value={target.targetId}>{target.name}</option>)}
          </select>
        </label>
        <label className="field-group">
          <span>Synthetic identity for tool and connector tests</span>
          <select value={identityId} onChange={(event) => setIdentityId(event.target.value)}>
            {data.identities.map((identity) => (
              <option key={identity.identity_id} value={identity.identity_id}>
                {identity.display_name} · {identity.tenant_id}
              </option>
            ))}
          </select>
        </label>
      </SectionCard>

      <div className="two-column-grid">
        <SectionCard title={`Synthetic identities (${data.identities.length})`} subtitle="Role and tenant-bound test identities; no passwords or tokens are stored.">
          <div className="lab-list">
            {data.identities.map((identity) => (
              <article key={identity.identity_id} className="lab-list-item">
                <strong>{identity.display_name}</strong>
                <span>{identity.roles.map(pretty).join(', ')} · {identity.tenant_id}</span>
                <code>{identity.identity_id}</code>
              </article>
            ))}
          </div>
        </SectionCard>
        <SectionCard title={`Protected resources (${data.resources.length})`} subtitle="Resource metadata only; direct resource contents are not displayed.">
          <div className="lab-list">
            {data.resources.map((resource) => (
              <article key={resource.resource_id} className="lab-list-item">
                <strong>{resource.display_name}</strong>
                <span>{pretty(resource.classification)} · {resource.tenant_id}</span>
                <code>{resource.resource_id}</code>
              </article>
            ))}
          </div>
        </SectionCard>
      </div>

      <SectionCard title={`RAG fixture documents (${data.documents.length})`} subtitle="Metadata-only inventory of local synthetic documents, including untrusted-instruction fixtures.">
        <div className="lab-list lab-list--grid">
          {data.documents.map((document) => (
            <article key={document.document_id} className="lab-list-item">
              <strong>{document.title}</strong>
              <span>{pretty(document.classification)} · {document.tenant_id}</span>
              <span>{document.contains_untrusted_instructions ? 'Contains untrusted instructions' : 'No untrusted instructions flagged'}</span>
              <code>{document.document_id}</code>
            </article>
          ))}
        </div>
        <ScenarioControl
          title="RAG security scenario"
          scenarios={ragScenarios}
          selected={selectedScenarios.rag}
          onSelect={(value) => updateScenario('rag', value)}
          onRun={() => void runScenario('rag')}
          running={running === 'rag'}
          result={results.rag}
        />
      </SectionCard>

      <div className="two-column-grid">
        <SectionCard title={`Local vector collections (${data.vectorCollections.length})`} subtitle="Persistent, local synthetic collections; searches apply the centralized authorization policy.">
          <div className="lab-list">
            {data.vectorCollections.map((collection) => (
              <article key={collection.collection_id} className="lab-list-item">
                <strong>{collection.display_name}</strong>
                <span>{collection.tenant_id}</span>
                <code>{collection.collection_id}</code>
              </article>
            ))}
            {!data.vectorCollections.length ? <p className="empty-copy">No synthetic vector collections are configured.</p> : null}
          </div>
          <label className="field-group">
            <span>Synthetic vector search</span>
            <input value={vectorQuery} onChange={(event) => setVectorQuery(event.target.value)} maxLength={1000} placeholder="Search local synthetic content" />
          </label>
          <button type="button" className="secondary-button" onClick={() => void searchVectors()} disabled={auxiliaryRunning || !vectorQuery.trim() || !data.vectorCollections.length}>
            <Play size={14} />Search with selected identity
          </button>
          {vectorResults.map(({ document, similarity }) => (
            <article key={document.document_id} className="lab-list-item">
              <strong>{document.title}</strong>
              <span>{document.tenant_id} · {pretty(document.classification)} · similarity {similarity.toFixed(3)}</span>
              <p>{document.content}</p>
            </article>
          ))}
        </SectionCard>
        <SectionCard title="Synthetic agent memory" subtitle="Inspect only memory records authorized for the selected synthetic identity and session.">
          <button type="button" className="secondary-button" onClick={() => void inspectMemory()} disabled={auxiliaryRunning || !identityId}>
            <ShieldCheck size={14} />Inspect authorized memory metadata
          </button>
          <div className="lab-list">
            {memoryRecords.map((memory) => (
              <article key={memory.memory_id} className="lab-list-item">
                <strong>{pretty(memory.scope)} memory · {pretty(memory.classification)}</strong>
                <span>{memory.tenant_id} · owner {memory.owner_identity_id}</span>
                <code>{memory.memory_id}</code>
              </article>
            ))}
            {!memoryRecords.length ? <p className="empty-copy">No authorized memory records loaded.</p> : null}
          </div>
        </SectionCard>
      </div>

      <SectionCard title="Synthetic web security fixture" subtitle="In-process control simulation only; this does not scan or contact any host.">
        <label className="field-group">
          <span>Controlled fixture</span>
          <select value={webFixtureId} onChange={(event) => setWebFixtureId(event.target.value)}>
            {data.webFixtures.map((fixture) => <option key={fixture.fixture_id} value={fixture.fixture_id}>{fixture.display_name}</option>)}
          </select>
        </label>
        <label className="field-group">
          <span>Control scenario</span>
          <select value={webTestId} onChange={(event) => setWebTestId(event.target.value)}>
            {data.webTests.map((test) => <option key={test.test_id} value={test.test_id}>{pretty(test.test_id)} · {pretty(test.category)}</option>)}
          </select>
        </label>
        <button type="button" className="secondary-button" onClick={() => void runWebFixture()} disabled={auxiliaryRunning || !webFixtureId || !webTestId}>
          <Play size={14} />Run local control simulation
        </button>
        {webRun?.results.map((result) => (
          <div key={result.evidence_id} className={`inline-message ${result.status === 'FAIL' ? 'inline-message--warning' : 'inline-message--success'}`} role="status">
            <strong>{pretty(result.status.toLowerCase())}: {pretty(result.category)}</strong>
            <span>{result.observed_behavior}</span>
            <span>Simulated evidence: <code>{result.evidence_reference}</code></span>
          </div>
        ))}
      </SectionCard>

      <div className="two-column-grid">
        <SectionCard title={`Simulated tools and MCP (${data.tools.length} tools · ${data.mcpServers.length} servers)`} subtitle="Only local simulated tools and MCP fixture metadata are available here.">
          <div className="lab-list">
            {data.tools.map((tool) => (
              <article key={tool.tool_id} className="lab-list-item">
                <strong>{tool.name}</strong>
                <span>{pretty(tool.operation)} · {pretty(tool.risk_classification)}</span>
              </article>
            ))}
            {data.mcpServers.map((server) => (
              <article key={server.server_id} className="lab-list-item">
                <strong>{server.display_name}</strong>
                <span>{pretty(server.trust_level)} · {server.simulated ? 'simulated' : 'not simulated'}</span>
              </article>
            ))}
            {data.mcpResources.map((resource) => (
              <article key={resource.resource_id} className="lab-list-item">
                <strong>{resource.display_name}</strong>
                <span>{resource.tenant_id} · {pretty(resource.classification)}</span>
              </article>
            ))}
          </div>
          <ScenarioControl
            title="Tool / MCP security scenario"
            scenarios={toolScenarios}
            selected={selectedScenarios.tools}
            onSelect={(value) => updateScenario('tools', value)}
            onRun={() => void runScenario('tools')}
            running={running === 'tools'}
            result={results.tools}
          />
        </SectionCard>

        <SectionCard title={`Synthetic integrations (${data.integrations.length})`} subtitle="Connectors execute only against local synthetic fixtures.">
          <div className="lab-list">
            {data.integrations.map((integration) => (
              <article key={integration.integration_id} className="lab-list-item">
                <strong>{integration.display_name}</strong>
                <span>{pretty(integration.provider_type)} · {integration.tenant_scope}</span>
                <span>{pretty(integration.data_classification)} · {integration.simulated_execution_mode}</span>
              </article>
            ))}
          </div>
          <ScenarioControl
            title="Connector security scenario"
            scenarios={integrationScenarios}
            selected={selectedScenarios.integrations}
            onSelect={(value) => updateScenario('integrations', value)}
            onRun={() => void runScenario('integrations')}
            running={running === 'integrations'}
            result={results.integrations}
          />
        </SectionCard>
      </div>

      <SectionCard title={`Authorization test scenarios (${authorizationScenarios.length})`} subtitle="The centralized policy engine returns the decision; natural-language claims do not grant access.">
        <ScenarioControl
          title="Authorization scenario"
          scenarios={authorizationScenarios}
          selected={selectedScenarios.authorization}
          onSelect={(value) => updateScenario('authorization', value)}
          onRun={() => void runScenario('authorization')}
          running={running === 'authorization'}
          result={results.authorization}
        />
      </SectionCard>

      <SectionCard title={`Attack library (${categories.length} categories)`} subtitle="Applicability is computed against the selected target's scope and capability profile.">
        {!targetId ? <p className="empty-copy">Add a target to view applicable categories.</p> : (
          <div className="lab-list lab-list--grid">
            {categories.map((category) => (
              <article key={category.category} className="lab-list-item">
                <strong>{pretty(category.category)}</strong>
                <span>{category.attack_count} registered case(s) · {category.applicable ? 'applicable' : 'not applicable'}</span>
                <span>Requires: {category.required_capabilities.map(pretty).join(', ') || 'model endpoint'}</span>
              </article>
            ))}
          </div>
        )}
      </SectionCard>
    </div>
  );
}
