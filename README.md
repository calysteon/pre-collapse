# Pre-Collapse: Vulnerability-Class Signatures in the Activation Space of Language Models

> **This is not only a position.** A working reference implementation of the
> (signature → patch) loop lives in [`engine/`](engine/): a small model reads code, its
> pre-collapse signature indexes a database that returns the patch for the class, and an
> AddressSanitizer oracle confirms the patch turns the crashing input safe. On a four-class
> corpus with `microsoft/phi-1_5`: 12/12 signature-selected patches verified end-to-end,
> 83% held-out class detection. See [`engine/README.md`](engine/README.md).

---

## The position

When a language model reads code, its activation space forms a specific, structured representation of that
code's latent vulnerability. It forms this representation before, and independently of, whatever the model is
later prompted to output. Each class of vulnerability produces a characteristic signature in that space. These
signatures are not passive readouts. They are causal: the same activation direction that identifies a
vulnerability class can be used to drive the model's behavior. A signature can therefore be associated with the
patch that fixes its class.

This changes the unit of security knowledge. For thirty years that unit has been a pair of the form (pattern,
label): a rule, a YARA signature, a CVE fingerprint, a trained classifier's decision boundary. We argue it
should be (activation signature, patch). Code is identified by the shape it produces in a model's
representation. That shape indexes a database of known vulnerability signatures. The matching entry already
contains the patch for that class of bug. Detection and patch selection become the same operation.

This is not a proposal for a better classifier. It is a claim about where the semantics of a program reside
when a model reads it, and about what follows once that location, the pre-collapse representation, is used as
an index over both bugs and their patches. The rest of this paper shows that the position is not speculative.
It is the point at which five established research programs meet.

---

## Two established facts, rarely connected

**The same bug appears in many places.** Software is built by copying. A vulnerable function is reused,
modified, and copied again across the ecosystem at large scale. In a study of 10,241 GitHub projects spanning
80 billion lines, modified reuse of components occurred about twenty times more often than exact reuse (Woo et
al., 2021). Up to 40% of npm packages transitively depend on code with a known vulnerability (Zimmermann et
al., 2019). When the original is patched, the copies usually are not. A cloned vulnerability commonly stays
exploitable for years after its source is fixed (Kim & Lee, 2018). In most cases the patch for a newly found
bug already exists in another codebase at the moment the bug is found. The hard part is not producing the fix.
It is establishing that this bug and that fix belong to the same vulnerability.

**A model represents more than it outputs.** A model's hidden state encodes whether a statement is true even
when the model states the opposite (Azaria & Mitchell, 2023). The correct judgment can be read from
activations without supervision, even when the model is prompted to answer incorrectly (Burns et al., 2023).
The internal representation is earlier and more accurate than the tokens the model produces.

These facts are usually studied apart. Put together, they imply something specific. If a model forms an
accurate internal representation of a vulnerability, and the same vulnerability recurs across codebases, then
that representation is the invariant needed to detect the recurrence and attach the correct patch to it.

---

## Activations are a semantic substrate, not a byproduct

That abstract properties are linearly encoded in a network's activations is one of the most robust findings in
interpretability. Linear classifier probes recover task-relevant structure from frozen intermediate features,
and that structure sharpens with depth (Alain & Bengio, 2016). The linear representation hypothesis, given a
rigorous formulation through counterfactual pairs and a causal inner product, establishes that a concept can
correspond to a direction that is both measurable and manipulable (Park, Choe & Veitch, 2024).

For code, the representation is genuinely semantic. Neural models reason about program behavior from structure
alone, without executing anything (Allamanis, Brockschmidt & Khademi, 2018), and can be trained to emulate a
program's execution internally (Bieber et al., 2020). The signal persists on stripped and decompiled binaries.
Cross-platform function semantics (Xu et al., 2017), jump-aware binary similarity (Wang et al., 2022), and
self-supervised assembly embeddings (Li, Qu & Yin, 2021) all read meaning off machine code with no source
present, and current models decompile binaries into faithful pseudocode directly (Tan et al., 2024).
Classifying the *type* of a vulnerability, its CWE class rather than its mere presence, is established prior
art (Zou et al., 2021). The semantics of code, down to the class of its defects, are linearly accessible in a
model's activations. That is the substrate this thesis stands on.

---

## Pre-collapse: the model's reading precedes its output

We call the central object pre-collapse: the representation of a problem as the model first forms it, before
task framing, decoding pressure, or adversarial context degrade it into a weaker output. The distinction is
not stylistic. Published results show the correct internal representation is present and recoverable even when
the output is wrong (Azaria & Mitchell, 2023; Burns et al., 2023). The degradation happens after the accurate
reading, not during it.

This matters because the vulnerability is clearest in the pre-collapse state. Ask a model in prose whether a
piece of code is exploitable and its answers are unstable; renaming a variable can flip the verdict. That
instability belongs to the output pathway, not to the representation. The accurate reading is already present
upstream. The place to read a vulnerability is not the model's stated answer but the signature it forms as soon
as it parses the code. Pre-collapse is that point, and the signature there is the cleanest one available.

---

## Signatures are causal, not just readable

A signature that could only be read would be of limited use. What makes it useful is that these representations
control behavior. Representation engineering reads high-level concepts as population-level activation
directions and adds them back to steer the model (Zou et al., 2023). A steering vector, computed as the
activation difference between a contrastive prompt pair and injected at inference without fine-tuning, shifts
behavior predictably (Turner et al., 2023). Averaged over many pairs, it becomes a reusable vector whose
magnitude scales the target behavior (Rimsky et al., 2024). Causal localization identifies where a behavior is
computed and edits it directly (Meng et al., 2022), building on causal-mediation methods that separate
representation that is present from representation the model actually uses (Vig et al., 2020).

For security the consequence is concrete. A vulnerability-class signature is not only a description of the
code. It can be read from code to detect the bug, and written back to elicit the model's understanding of it.
The signature is both the index and the control input. That is what a database keyed on signatures needs.

---

## Keying the database on signatures, not syntax

The machinery for "capture a vulnerability once and find it everywhere" already exists. It has been built on
the wrong representation.

A decade of work established the approach. ReDeBug scans whole operating-system distributions for unpatched
clones of a known-buggy fragment (Jang, Agrawal & Brumley, 2012). VUDDY fingerprints vulnerable functions and
scans a billion lines of code in hours, finding real zero-days (Kim et al., 2017). The important step is the
patch signature. MVP extracts a vulnerability signature and a patch signature, and flags a target only when it
matches the first and not the second, which separates a still-vulnerable clone from one that has been fixed
(Xiao et al., 2020). That is the (signature, patch) mechanism in operation. It also handles more than exact
copies. MOVERY detects modified vulnerable clones and reports that 91% of the clones it finds differ
syntactically from the original (Woo et al., 2022), which shows the useful signature is semantic rather than
textual. FIBER runs the same patch-presence test on binaries (Zhang & Qian, 2018). The patch side of the
database can be populated automatically, because silent security fixes are detectable in commit history (Zhou
et al., 2023; Tang et al., 2025).

The patching side is established too. A patch for one instance of a bug can be applied to another. CodePhage
transplants a correct check from a donor program into a recipient that mishandles the same input, working from
binary donors with no source (Sidiroglou-Douskos et al., 2015). PatchWeave adapts a donor patch to a similar
target, including Heartbleed-class fixes across OpenSSL variants (Shariffdeen et al., 2021). Getafix mines
human fix patterns and runs in production, predicting the exact human fix as its top suggestion for recurring
bug classes (Bader et al., 2019).

All of these systems match on tokens, slices, or control-flow graphs. All of them are pushed into increasingly
complex abstractions by one problem: ordinary code modification, which MOVERY's own measurement shows defeats
syntactic matching in most real cases. Free-form learned detectors do worse, fitting project-specific surface
features and failing across projects (Chakraborty et al., 2022). The approach is sound. The representation is
not. The property that survives modification is the model's semantic reading of the code, and that reading is
the pre-collapse activation signature. Key the database on the signature, and modification, renaming, and
refactoring stop mattering, because they were never part of what the model represented. Each entry becomes
(activation signature of a vulnerability class, patch that fixes it), and every system above gains an index
that does not depend on the surface form it was fighting.

This changes how vulnerability research operates. It is no longer only a search for unknown bugs. It becomes
detection, across the whole ecosystem, of where a known bug recurs, including where it was reintroduced
independently or copied and modified past syntactic recognition, followed by application of the patch already
associated with it. A patch validated on a small repository can be applied to the same bug in a codebase far
larger, because both produce the same signature.

---

## Semantic structure survives obfuscation

That semantic structure survives what changes the surface is not a new claim. It is a founding result of
malware analysis. Purely syntactic signatures fail against obfuscation because they ignore instruction
semantics, while semantics-aware detection resists it (Christodorescu et al., 2005). This was later given
formal footing, with provable resistance to defined classes of obfuscation (Dalla Preda et al., 2007), and
carried into graph-based learning (survey, 2023). The activation signature is the endpoint of this line of
work. An obfuscator can rename identifiers, flatten control flow, and reorder instructions, but it cannot
easily change what the code does, and behavior is what the model represents. Recent work shows that
latent-space probes read behavioral properties the surface is designed to hide (Bailey et al., 2024).
Obfuscation transforms syntax. The pre-collapse signature depends on semantics. The two do not intersect.

---

## Reading weird machines in latent space

Exploitation can be described as programming a weird machine: forcing a target into unintended computation
present in its own structure, using crafted input as the program (Bratus et al., 2011). This was given formal
treatment through the theory of the emergent weird machine and provable unexploitability (Dullien, 2020). The
thesis extends to this setting. A model reading an exploit primitive or an obfuscated payload does not run it.
It forms a representation of what the code would do, and the capacity for that kind of internal emulation is
established, not assumed. Transformers are Turing-complete in principle (Pérez et al., 2019). A looped
transformer can emulate a general-purpose computer (Giannou et al., 2023). A single attention layer can carry
out a step of gradient descent, which makes in-context learning a form of internal optimization (von Oswald et
al., 2023). When a model reads obfuscated or exploit-bearing code, its activation trajectory is a semantic
emulation of that code. It exposes the weird-machine structure the syntax was written to hide, without running
the code and without the model producing any output.

---

## Signal in natural language, not just code

Vulnerabilities are described in language as well as in code, and that language carries recoverable,
exploit-predictive signal. Mining public posts predicts which vulnerabilities will be exploited in the wild
(Sabottke et al., 2015), often before an official severity score is published (Chen et al., 2019). The text of
underground discussion, not only its metadata, predicts exploitation (Tavabi et al., 2018). Technical
write-ups around a disclosure improve prediction of a working exploit (Suciu et al., 2022), and specific
technical indicators can be extracted reliably from unstructured prose (Liao et al., 2016; Du et al., 2023).
Exploit prediction is already used in industry (Jacobs et al., 2021).

This completes the supply-chain argument. A description of a bug, whether a commit message, an advisory, a
screenshot of a stack trace, or a public post, is an index into the same signature space. The natural-language
description of a small project's fix can be mapped, through that shared space, to the same bug in a larger
codebase. The pointer that connects a known bug to its unknown copies does not have to be code.

---

## Small models make ecosystem-scale scanning practical

None of this requires a frontier model. The Phi results show that data quality can substitute for scale. A
1.3B model outperforms much larger code models (Gunasekar et al., 2023). A 3.8B model matches systems an order
of magnitude larger while running on a phone (Abdin et al., 2024a). The current generation performs well for
its size on reasoning tasks (Abdin et al., 2024b). A model this size can read every function in an ecosystem,
cheaply and continuously. The cost that makes ecosystem-wide scanning impractical for a frontier model makes
it routine for a 3.8-billion-parameter one. The signature representation is more stable than syntax, and it is
deployable at the scale the problem has.

---

## The position, restated

The components are all established, and they have not been combined. Activations encode the semantics of code,
including the class of its defects. That representation exists in an accurate, pre-collapse form before the
output degrades it. These representations are causal, both readable and writable. Vulnerabilities recur widely,
and their patches already exist. Matching them currently fails only because it is done on the surface form,
which modification defeats, while the semantic signature it should use is exactly what a small, inexpensive
model produces as soon as it reads the code.

Associate the signature with the patch, and vulnerability research changes character. It moves from an
open-ended search for unknown bugs to systematic detection of where known bugs recur, with the corresponding
patch attached, across an ecosystem that copies faster than it patches. The activation signature is what links
a known bug to its copies, and the pre-collapse representation is where that link is found.

---

## Reference implementation

[`engine/`](engine/) makes the loop concrete and runnable end to end:

- **Signature** — a small model (`microsoft/phi-1_5`) reads each program; the mean-pooled
  hidden states over a deep layer band reduce to one L2-normalized vector (`signature.py`).
- **Index = patch selection** — the vector's nearest class centroid is looked up; that single
  lookup returns both the vulnerability class and the patch for it (`database.py`).
- **Patch** — the class's donor fix, matched on idiom rather than identifiers so it survives
  renaming, is applied to the code (`patch.py`).
- **Ground truth** — the patched program is compiled under AddressSanitizer and run on the
  same proof-of-concept input that crashed the original; only a VULNERABLE→SAFE transition
  counts as a fix (`oracle.py`).

The corpus is four memory-safety classes (CWE-121/122/190/416), each with a canonical case
plus renamed and refactored clones. Results on this set: **12/12** signature-selected patches
confirmed by the oracle (all clones included), **83%** held-out (leave-one-out) class
detection versus 25% chance — with the residual errors falling exactly between the two
classes that share a heap out-of-bounds write. The whole loop runs offline from committed
signatures; the model path regenerates them. This demonstrates the mechanism at small scale;
the ecosystem-scale database the position argues for is future work, not a claim made here.

---

## References

Abdin, M., et al. (2024a). *Phi-3 Technical Report: A Highly Capable Language Model Locally on Your Phone.* arXiv:2404.14219.
Abdin, M., et al. (2024b). *Phi-4 Technical Report.* arXiv:2412.08905.
Alain, G., & Bengio, Y. (2016). *Understanding intermediate layers using linear classifier probes.* arXiv:1610.01644.
Allamanis, M., Brockschmidt, M., & Khademi, M. (2018). *Learning to Represent Programs with Graphs.* ICLR. arXiv:1711.00740.
Azaria, A., & Mitchell, T. (2023). *The Internal State of an LLM Knows When It's Lying.* Findings of EMNLP. arXiv:2304.13734.
Bader, J., Scott, A., Pradel, M., & Chandra, S. (2019). *Getafix: Learning to Fix Bugs Automatically.* OOPSLA / PACMPL. DOI 10.1145/3360585.
Bailey, L., et al. (2024). *Obfuscated Activations Bypass LLM Latent-Space Defenses.* arXiv:2412.09565.
Bieber, D., Sutton, C., Larochelle, H., & Tarlow, D. (2020). *Learning to Execute Programs with Instruction Pointer Attention Graph Neural Networks.* NeurIPS. arXiv:2010.12621.
Bratus, S., Locasto, M. E., Patterson, M. L., Sassaman, L., & Shubina, A. (2011). *Exploit Programming: From Buffer Overflows to Weird Machines and Theory of Computation.* USENIX ;login: 36(6).
Burns, C., Ye, H., Klein, D., & Steinhardt, J. (2023). *Discovering Latent Knowledge in Language Models Without Supervision.* ICLR. arXiv:2212.03827.
Chakraborty, S., Krishna, R., Ding, Y., & Ray, B. (2022). *Deep Learning based Vulnerability Detection: Are We There Yet?* IEEE TSE. DOI 10.1109/TSE.2021.3087402.
Chen, H., Liu, R., Park, N., & Subrahmanian, V. S. (2019). *Using Twitter to Predict When Vulnerabilities will be Exploited.* KDD. DOI 10.1145/3292500.3330742.
Christodorescu, M., Jha, S., Seshia, S. A., Song, D., & Bryant, R. E. (2005). *Semantics-Aware Malware Detection.* IEEE S&P. DOI 10.1109/SP.2005.20.
Dalla Preda, M., Christodorescu, M., Jha, S., & Debray, S. (2007). *A Semantics-Based Approach to Malware Detection.* ACM POPL.
Du, Q., Huang, H., et al. (2023). *ExpSeeker: Extract Public Exploit Code Information from Social Media.* Applied Intelligence 53. DOI 10.1007/s10489-022-04178-9.
Dullien, T. (2020). *Weird Machines, Exploitability, and Provable Unexploitability.* IEEE Trans. Emerging Topics in Computing 8(2). DOI 10.1109/TETC.2017.2785299.
Giannou, A., Rajput, S., Sohn, J.-Y., Lee, K., Lee, J. D., & Papailiopoulos, D. (2023). *Looped Transformers as Programmable Computers.* ICML. arXiv:2301.13196.
Gunasekar, S., et al. (2023). *Textbooks Are All You Need (phi-1).* arXiv:2306.11644.
Jacobs, J., Romanosky, S., Edwards, B., Roytman, M., & Adjerid, I. (2021). *Exploit Prediction Scoring System (EPSS).* Digital Threats: Research and Practice 2(3). arXiv:1908.04856.
Jang, J., Agrawal, A., & Brumley, D. (2012). *ReDeBug: Finding Unpatched Code Clones in Entire OS Distributions.* IEEE S&P. DOI 10.1109/SP.2012.13.
Kim, S., & Lee, H. (2018). *Software systems at risk: An empirical study of cloned vulnerabilities in practice.* Computers & Security 77. DOI 10.1016/j.cose.2018.02.007.
Kim, S., Woo, S., Lee, H., & Oh, H. (2017). *VUDDY: A Scalable Approach for Vulnerable Code Clone Discovery.* IEEE S&P.
Li, X., Qu, Y., & Yin, H. (2021). *PalmTree: Learning an Assembly Language Model for Instruction Embedding.* ACM CCS. arXiv:2103.03809.
Liao, X., Yuan, K., Wang, X., Li, Z., Xing, L., & Beyah, R. (2016). *Acing the IOC Game: Toward Automatic Discovery and Analysis of Open-Source Cyber Threat Intelligence (iACE).* ACM CCS. DOI 10.1145/2976749.2978315.
Meng, K., Bau, D., Andonian, A., & Belinkov, Y. (2022). *Locating and Editing Factual Associations in GPT (ROME).* NeurIPS. arXiv:2202.05262.
Park, K., Choe, Y. J., & Veitch, V. (2024). *The Linear Representation Hypothesis and the Geometry of Large Language Models.* ICML. arXiv:2311.03658.
Pérez, J., Marinković, J., & Barceló, P. (2019). *On the Turing Completeness of Modern Neural Network Architectures.* ICLR. arXiv:1901.03429.
Rimsky, N., Gabrieli, N., Schulz, J., Tong, M., Hubinger, E., & Turner, A. M. (2024). *Steering Llama 2 via Contrastive Activation Addition.* ACL. arXiv:2312.06681.
Sabottke, C., Suciu, O., & Dumitraș, T. (2015). *Vulnerability Disclosure in the Age of Social Media: Exploiting Twitter for Predicting Real-World Exploits.* USENIX Security.
Shariffdeen, R., Tan, S. H., Gao, M., & Roychoudhury, A. (2021). *Automated Patch Transplantation (PatchWeave).* ACM TOSEM. DOI 10.1145/3412376.
Sidiroglou-Douskos, S., Lahtinen, E., Long, F., & Rinard, M. (2015). *Automatic Error Elimination by Horizontal Code Transfer across Multiple Applications (CodePhage).* PLDI. DOI 10.1145/2813885.2737988.
*Survey of Malware Analysis through Control Flow Graph using Machine Learning.* (2023). arXiv:2305.08993.
Suciu, O., Nelson, C., Lyu, Z., Bao, T., & Dumitraș, T. (2022). *Expected Exploitability: Predicting the Development of Functional Vulnerability Exploits.* USENIX Security. arXiv:2102.07869.
Tan, H., Luo, Q., Li, J., & Zhang, Y. (2024). *LLM4Decompile: Decompiling Binary Code with Large Language Models.* EMNLP. arXiv:2403.05286.
Tang, X., et al. (2025). *Just-in-Time Detection of Silent Security Patches.* ACM TOSEM. arXiv:2312.01241.
Tavabi, N., Goyal, P., Almukaynizi, M., Shakarian, P., & Lerman, K. (2018). *DarkEmbed: Exploit Prediction With Neural Language Models.* AAAI.
Turner, A. M., Thiergart, L., Leech, G., Udell, D., Vazquez, J. J., et al. (2023). *Steering Language Models With Activation Engineering (Activation Addition).* arXiv:2308.10248.
Vig, J., Gehrmann, S., Belinkov, Y., Qian, S., Nevo, D., Singer, Y., & Shieber, S. (2020). *Investigating Gender Bias in Language Models Using Causal Mediation Analysis.* NeurIPS. arXiv:2004.12265.
von Oswald, J., Niklasson, E., Randazzo, E., Sacramento, J., Mordvintsev, A., Zhmoginov, A., & Vladymyrov, M. (2023). *Transformers Learn In-Context by Gradient Descent.* ICML.
Wang, H., Qu, W., et al. (2022). *jTrans: Jump-Aware Transformer for Binary Code Similarity Detection.* ISSTA. arXiv:2205.12713.
Woo, S., Hong, H., Choi, E., & Lee, H. (2022). *MOVERY: A Precise Approach for Modified Vulnerable Code Clone Discovery.* USENIX Security.
Woo, S., Park, S., Kim, S., Lee, H., & Oh, H. (2021). *CENTRIS: A Precise and Scalable Approach for Identifying Modified Open-Source Software Reuse.* ICSE. arXiv:2102.06182.
Xiao, Y., Chen, B., Yu, C., Xu, Z., Yuan, Z., Li, F., Liu, B., Liu, Y., Huo, W., Zou, W., & Shi, W. (2020). *MVP: Detecting Vulnerabilities using Patch-Enhanced Vulnerability Signatures.* USENIX Security.
Xu, X., Liu, C., Feng, Q., Yin, H., Song, L., & Song, D. (2017). *Neural Network-based Graph Embedding for Cross-Platform Binary Code Similarity Detection (Gemini).* ACM CCS. arXiv:1708.06525.
Zhang, H., & Qian, Z. (2018). *Precise and Accurate Patch Presence Test for Binaries (FIBER).* USENIX Security.
Zhou, J., Pacheco, M., Chen, J., Hu, X., Xia, X., Lo, D., & Hassan, A. E. (2023). *CoLeFunDa: Explainable Silent Vulnerability Fix Identification.* ICSE.
Zimmermann, M., Staicu, C.-A., Tenny, C., & Pradel, M. (2019). *Small World with High Risks: A Study of Security Threats in the npm Ecosystem.* USENIX Security. arXiv:1902.09217.
Zou, A., Phan, L., Chen, S., Campbell, J., Guo, P., et al. (2023). *Representation Engineering: A Top-Down Approach to AI Transparency.* arXiv:2310.01405.
Zou, D., Wang, S., Xu, S., Li, Z., & Jin, H. (2021). *μVulDeePecker: A Deep Learning-Based System for Multiclass Vulnerability Detection.* IEEE TDSC. DOI 10.1109/TDSC.2019.2942930.
