# TrigFuzz

Official code repository for the research paper *TrigFuzz: Triggering Conditions Guided Directed Fuzzing* (IEEE S&P 2026). We will release the code soon.

## Paper

[PDF](https://vul337.github.io/TrigFuzz/trigfuzz.pdf)

<p>
  <a href="https://vul337.github.io/TrigFuzz/trigfuzz.pdf">
    <img src="docs/trigfuzz-page1.png" alt="First page of the TrigFuzz paper" width="700">
  </a>
</p>

## Citation

```bibtex
@inproceedings{chen2026trigfuzz,
  author = {Chen, Yiyang and Gui, Nuoqi and Wang, Long and Chen, Longfei and Shi, Xuanqing and Cao, Xi and Zhang, Chao},
  booktitle = {2026 IEEE Symposium on Security and Privacy (SP)},
  title = {{TrigFuzz: Triggering Conditions Guided Directed Fuzzing}},
  year = {2026},
  volume = {},
  ISSN = {2375-1207},
  isbn = {979-8-3315-6065-2},
  pages = {3357-3375},
  abstract = {Directed fuzzing aims to trigger specific vulnerabilities by steering execution towards predefined target code. However, state-of-the-art directed fuzzers predominantly focus on reaching the target code quickly, often lacking effective follow-up strategies to satisfy the vulnerability constraints required to trigger them. We find that this can be a key factor limiting their performance in directed fuzzing tasks such as crash reproduction. The main challenge is that existing directed fuzzers cannot accurately identify the triggering conditions of target vulnerabilities and effectively exploit them to guide fuzzing. To address this challenge, we propose TrigFuzz, a directed fuzzing solution guided by triggering conditions. Our approach leverages pre-trained large language models (LLMs) to automatically generate the triggering conditions of target vulnerabilities. We design a formalized representation for generated triggering conditions, along with a novel dynamic triggering validation technique to verify their correctness. The verified conditions are further transformed into ``triggering distance'' metrics that serve as fuzzing runtime feedback to guide seed scheduling and mutation strategies, enabling directed fuzzing to effectively generate vulnerability-triggering test cases. Our evaluations demonstrate that TrigFuzz can generate high-quality triggering conditions for 96.67% of target vulnerabilities and outperform state-of-the-art directed fuzzers with over a 1.72x speedup in reproducing target vulnerabilities on the benchmark Magma. Lastly, we detected 7 previously unknown vulnerabilities with 2 CVE IDs assigned in well-tested real-world software using TrigFuzz.},
  keywords = {},
  doi = {10.1109/SP63933.2026.00156},
  url = {https://doi.ieeecomputersociety.org/10.1109/SP63933.2026.00156},
  publisher = {IEEE Computer Society},
  address = {Los Alamitos, CA, USA},
  month = {May},
}
```
