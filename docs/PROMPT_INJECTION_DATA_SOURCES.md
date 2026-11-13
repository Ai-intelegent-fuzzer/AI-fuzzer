# Prompt-injection dataset source and license review

**Reviewed:** 2026-11-12
**Workspace branch:** `feature/application-aware-security`
**Acquisition status:** Source pages and repository metadata reviewed; no source dataset files were downloaded or copied into this repository.

This is a research and licensing inventory, not a grant of rights or legal advice. A repository-level software license is not automatically a dataset license. Dataset content is not reproduced here.

## Primary sources

| Source | Official source / paper | Pin observed during review | License / access | Published size and content | Decision |
|---|---|---|---|---|---|
| LLMail-Inject | [Hugging Face dataset](https://huggingface.co/datasets/microsoft/llmail-inject-challenge); [2026 ACL Anthology paper](https://aclanthology.org/2026.findings-emnlp.514/); [arXiv](https://arxiv.org/abs/2506.09956) | HF revision `1063bdf01ec8762b812d5e06ee768a06faa5a6f7` | HF card declares MIT. Confirm that the card's grant covers each data file and any third-party material before redistribution. Public, not gated. | Paper reports 208,095 distinct human-written attacks and 839 participants. Dataset metadata lists two raw submission phases and curated labeled subsets. | Metadata only. No raw records copied; operational attack corpus not imported. |
| Tensor Trust | [Project and data release](https://tensortrust.ai/paper/); [paper](https://arxiv.org/abs/2311.01011) | No immutable release SHA surfaced on the reviewed page. | The reviewed official project page describes release of data and code, but no explicit dataset license/version was found in the accessible page. | Paper reports over 126,000 attacks and 46,000 defenses. Preserve those as separate populations if a licensed research process is approved. | Quarantined pending an explicit dataset license and pinned release. |
| HackAPrompt | [Dataset card](https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset); [paper](https://arxiv.org/abs/2311.16119); [official paper site](https://paper.hackaprompt.com/) | HF revision `25b87fbedfb86840abaf8cd09af7a029208a971a` | HF metadata declares MIT, but dataset access is `gated:auto` and requires agreeing to share account information. The gate was not accepted or bypassed. Dataset card warns that submissions were not curated and may contain offensive material. | Paper/site reports 41,596 official submissions and 560,161 playground prompts (601,757 total). | Not acquired: gated dataset access was not requested or bypassed. Licensing and privacy review still needed. |
| InjecAgent | [Official repository](https://github.com/uiuc-kang-lab/InjecAgent); [paper](https://arxiv.org/abs/2403.02691) | Repository HEAD `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` | Repository contains a file named `LICENCE` declaring MIT for the software and associated documentation. The dataset files were not separately assessed for rights, provenance, or third-party content. | README reports 1,054 composite test cases, covering 17 user tools and 62 attacker tools; raw attacker/user JSONL and derived test-case files are listed in the repository. | Metadata only. Dataset redistribution scope needs explicit confirmation; no cases imported or made executable. |
| Microsoft BIPIA | [Official repository](https://github.com/microsoft/BIPIA); [paper](https://arxiv.org/abs/2312.14197); [benchmark README](https://github.com/microsoft/BIPIA/blob/main/benchmark/README.md) | Repository HEAD `a004b69ec0dd446e0afd461d98cb5e96e120a5d0` | Repository license says MIT applies to code except specifically listed datasets. It identifies WikiTableQuestions and Stack Exchange material as CC BY-SA 4.0 and invoice data as MIT. README says WebQA and summarization contexts must be generated from upstream sources because of licensing. The attack files and each context component need separate review. | Covers EmailQA, WebQA, TableQA, summarization, and CodeQA contexts plus text/code attack files; no single total row count was confirmed from reviewed metadata. | No material imported. Dataset-specific terms and attribution must be resolved per file; source contexts must not be redistributed contrary to upstream terms. |
| AgentDojo | [Official repository](https://github.com/ethz-spylab/agentdojo); [paper](https://arxiv.org/abs/2406.13352) | Repository HEAD `089ed468cf3ed0322acc66b0211f26d9d90dbf60` | Repository-level MIT license verified. Separate provenance/terms for bundled benchmark data and third-party context were not independently established. | Paper reports 97 tasks and 629 security test cases; this is a paper snapshot, not a row count verified against current repository data. | No records copied or adapted. Any future use should pin a release and check terms for data assets separately. |
| NVIDIA Garak | [Official repository](https://github.com/NVIDIA/garak); [paper](https://arxiv.org/abs/2406.11036) | Repository HEAD `892779207cbc38f65a738ef9cbdfbc1e83aa0b55` | Repository declares Apache-2.0. That is a code license; individual probe provenance/content must still be reviewed before copying. | Probe plugins are executable test logic, not a fixed independent corpus with a stable row count. Prompt-injection probe module names were inspected; probe payloads were not copied. | No probes or payloads imported. Keep upstream attribution and license notices if a future, bounded use is separately approved. |
| deepset Prompt Injections | [Dataset page/card](https://huggingface.co/datasets/deepset/prompt-injections) | HF revision `4f61ecb038e9c3fb77e21034b22511b523772cdd` | Card metadata has a conflict: the dataset repository declares Apache-2.0 while `dataset_info` declares CC BY 4.0. Do not select one license by assumption. | 662 rows reported: 546 train and 116 test; text and integer label columns. | Quarantined pending owner clarification of the applicable dataset license and label semantics. Benign controls must remain separately labeled if reviewed later. |

## Additional research

| Candidate | Official source / paper | Review result |
|---|---|---|
| Amazon Science Task-Tampering Prompt Injection | [Official repository](https://github.com/amazon-science/task-tampering-prompt-injection); [arXiv 2611.07640](https://arxiv.org/abs/2611.07640) | Repository reports 90 cases and 1,433 injection variants. Dataset/code are marked CC BY-NC 4.0, with release described as academic/scientific reproducibility. Repository HEAD observed as `804b00dd03051c00e5e3000982bbf7ce2b9d9ad5`. No files copied; non-commercial terms and executable agent scenarios require separate review. |
| SWE-Inject | [Candidate repository](https://github.com/ArsalanKaleem/swe-inject) | Found during GitHub repository search. Not independently validated against a publication, stable release, or clear dataset license during this review; excluded from acquisition decisions. |
| OWASP security-project resources | [OWASP GenAI Security Project](https://genai.owasp.org/); [OWASP MCP Top 10](https://owasp.org/projects/mcp-top-10) | Taxonomies and defensive guidance for GenAI/MCP risks; not an original attack-record dataset and not counted as acquired data. |

Search results are not a complete census. Newly discovered repositories are candidates, not trusted sources, until their origin, release, and data rights are verified.

## Acquisition and transformation log

- **Metadata review date:** 2026-11-12.
- **Datasets/files downloaded into the workspace:** 0.
- **Payload records imported:** 0.
- **Transformations or mutations performed:** 0.
- **Checksums of data files:** Not applicable; no data files were acquired.
- **Reason:** This work records source metadata and licensing status only. It does not collect or operationalize attack payload corpora. Gated content was not accessed; ambiguous and component-specific terms were quarantined rather than inferred.

## References checked

Primary repository/dataset cards, the associated papers, project landing pages, and the license/benchmark README pages linked above were consulted. Repository/Hugging Face revision IDs are snapshots observed on the review date; they are not claims that dataset files were downloaded or verified locally.
