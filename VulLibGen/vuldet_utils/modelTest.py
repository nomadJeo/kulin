import os
os.environ["CUDA_VISIBLE_DEVICES"] = "6"
from unsloth import FastLanguageModel
import json
from tqdm import tqdm
import torch

max_seq_length = 2048
dtype = None
load_in_4bit = True

prompt_style = """Below is an instruction that describes a task, paired with an input that provides further context.  
Write a response that strictly follows the specified output format.

### Instruction:  
You are a security expert tasked with analyzing multi-source vulnerability data. Your goal is to extract affected package information and generate a structured output based on the given data.

#### **1. Data Sources & Consistency Handling**  
- The input includes vulnerability data aggregated from multiple sources:  
  - **NVD (National Vulnerability Database)**  
  - **GitHub Advisory Database**  
  - **Snyk Security Database**  
  - **Official package manager repositories (e.g., crates.io, PyPI, npm, Maven Central)**  
  - **Official package documentation or vendor advisories**  
- These sources may contain **overlapping**, **incomplete**, or **potentially inconsistent** information.  
- The output must **cross-check data** across sources and **resolve conflicts using a priority order**:  
  1. **official package manager data** (most reliable)  
  2. **Snyk Security Database** and **GitHub Advisory**
  3. **NVD** (useful but sometimes lacks package-level precision)  

#### **2. Output Format**  
- The response must be a JSON-like array.  
- Each element in the array must be a sub-array with exactly **three elements**:  
  1. **Ecosystem (string)** – Identify the ecosystem of the affected package (e.g., `"maven"`, `"pypi"`, `"crates.io"`, `"debian:unstable"`).  
  2. **Package Name (string)** – Provide the exact affected package name without modification.  
  3. **Version Ranges (array of strings)** – List affected versions using the following format:  
     - `[start_version, end_version)`: Left-closed, right-open (inclusive of `start_version`, exclusive of `end_version`).  
     - `(*, end_version]`: Left-open, right-closed (includes all versions up to `end_version`).  
     - `[start_version, start_version]`: Exact version match.  

#### **3. Handling Data Conflicts & Incomplete Information**  
- **If multiple sources report different affected version ranges**, use the most precise and restrictive range.  
- **If a source lacks key details (e.g., missing affected versions)**, infer missing data from more complete sources.  
- **If a package name differs across sources**, prefer the name from **GitHub Advisory** or **Snyk Security Database**.  
- **Do not include duplicate entries**; merge overlapping records when possible.  

#### **4. Output at most 10 affected libraries**  
- If the number of affected libraries exceeds 10, select the **top 10** based on:  
  - **Popularity** (e.g., GitHub stars, download count).  
  - **Breadth of affected versions** (packages affecting more versions rank higher).  

#### **5. Example Output Format**  
- Example valid output:
    ```json
    [
        ["maven", "org.apache.shiro:shiro-core", ["[1.2.0, 1.6.0)", "[1.7.0, 1.7.1]"]],
        ["pypi", "django", ["(*, 3.1.4]"]]
    ]
    ```

### Question:
{}

### Response:
{}"""

# Load the fine-tuned model TODO
model, tokenizer = FastLanguageModel.from_pretrained(
    # "/nvme2n1/YangYJworks/lxk/myTrain/outputs/deepseek-llama-8b-final/best_model",
    # "/nvme2n1/YangYJworks/lxk/myTrain/outputs/deepseek-qwen-7b/checkpoint-1000",
    "/nvme2n1/YangYJworks/lxk/myTrain/outputs/deepseek-Llama-8b_4_19/checkpoint-1000",
    max_seq_length = max_seq_length,
    dtype = dtype,
    load_in_4bit = load_in_4bit,
)

# 不微调 TODO
# model, tokenizer = FastLanguageModel.from_pretrained(
#     # model_name = "unsloth/DeepSeek-R1-Distill-Llama-8B",  # 替换为你的模型名称
#     model_name = "unsloth/DeepSeek-R1-Distill-Qwen-14B",  # 替换为你的模型名称
#     max_seq_length = max_seq_length,  # 最大序列长度
#     dtype = None,           # 自动选择数据类型（推荐）
#     load_in_4bit = True,    # 4-bit 量化减少显存占用
#     trust_remote_code=True,
# )
EOS_TOKEN = tokenizer.eos_token

# Load the test dataset TODO
test_dataset = json.loads(open('/nvme2n1/YangYJworks/lxk/xjw/dataset/test.json').read())
FastLanguageModel.for_inference(model)  # Unsloth has 2x faster inference!
# Perform predictions on the test dataset
results = []
for data in tqdm(test_dataset, desc="testing"):
    question = data['input']
    label = data['output']
    cve_id = data['cve_id']
    inputs = tokenizer([prompt_style.format(question, "")], return_tensors="pt").to("cuda")
    outputs = model.generate(
        input_ids=inputs.input_ids,
        attention_mask=inputs.attention_mask,
        max_new_tokens=512,
        use_cache=True,
    )
    response = tokenizer.batch_decode(outputs)
    results.append({
        "cve_id": cve_id,
        "input": question,
        "output": response[0].split("### Response:")[1].replace(EOS_TOKEN, "").strip(),
        "label": label,
    })
    # 释放显存
    del inputs, outputs
    torch.cuda.empty_cache()
    # break

# Save predictions to a file TODO
with open("results—4_19.json", "w") as f:
    json.dump(results, f, indent=2)