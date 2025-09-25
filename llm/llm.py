import os
import time

import dashscope
from openai import OpenAI
from dotenv import load_dotenv


# 设置全局代理
# os.environ["http_proxy"] = "http://127.0.0.1:7890"
# os.environ["https_proxy"] = "http://127.0.0.1:7890"
load_dotenv()

class BaseClient:
    """所有 AI Client 的基类，包含失败重试机制"""

    def __init__(self, model_name: str, api_key_env: str, base_url: str = None):
        self.model_name = model_name
        self.api_key = os.getenv(api_key_env)

        if not self.api_key:
            raise ValueError(f"API Key 未找到，请设置环境变量 {api_key_env}")

        self.base_url = base_url

    def _retry(self, func, *args, **kwargs):
        """执行带有重试机制的 API 调用"""
        wait_times = [2, 4, 8, 16]  # 失败后等待的时间（秒）
        for attempt, wait_time in enumerate(wait_times, start=1):
            try:
                return func(*args, **kwargs)  # 调用成功，直接返回结果
            except Exception as e:
                print(f"第 {attempt} 次尝试失败，错误: {str(e)}，等待 {wait_time} 秒后重试...")
                time.sleep(wait_time)

        print("thinking failure...")
        return "thinking failure..."


class DeepSeekClient(BaseClient):
    def __init__(self, model_name: str):
        super().__init__(model_name, "ALI_API_KEY", "https://dashscope.aliyuncs.com/compatible-mode/v1")
        self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)

    def Think(self, prompts: list) -> str:
        return self._retry(self._call_api, prompts)

    def _call_api(self, prompts):
        """实际发送请求的方法"""
        completion = self.client.chat.completions.create(
            model=self.model_name,
            messages=prompts
        )
        return completion.choices[0].message.content


class QwenClient(BaseClient):
    def __init__(self, model_name: str = "qwen-plus"):
        super().__init__(model_name, "ALI_API_KEY", "https://dashscope.aliyuncs.com/compatible-mode/v1")
        self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)

    def Think(self, prompts: list) -> str:
        return self._retry(self._call_api, prompts)

    def _call_api(self, prompts):
        completion = self.client.chat.completions.create(
            model=self.model_name,
            messages=prompts
        )
        return completion.choices[0].message.content

class LlamaClient(BaseClient):
    def __init__(self, model_name: str = "llama3.3-70b-instruct"):
        super().__init__(model_name, "ALI_API_KEY", "https://dashscope.aliyuncs.com/compatible-mode/v1")

    def Think(self, prompts: list) -> str:
        return self._retry(self._call_api, prompts)

    def _call_api(self, prompts):
        response = dashscope.Generation.call(
            api_key=self.api_key,
            model=self.model_name,
            messages=prompts,
            result_format="message",
        )

        if response.status_code == 200:
            return response.output.choices[0].message.content
        else:
            raise Exception(f"请求失败: {response.status_code}, 错误代码: {response.code}, 错误信息: {response.message}")

# 示例用法
if __name__ == "__main__":
    # DeepSeek 示例
    deepseek_client = DeepSeekClient(model_name="deepseek-r1")
    deepseek_response = deepseek_client.Think([{"role": "user", "content": "9.9和9.11谁大"}])
    print("DeepSeek 最终答案：", deepseek_response)

    # Qwen 示例
    qwen_client = QwenClient(model_name="qwen-plus")
    qwen_response = qwen_client.Think([{"role": "user", "content": "你是谁？"}])
    print("Qwen 最终答案：", qwen_response)

    # # GPT 示例
    # gpt_client = GPTClient(model_name="gpt-4o-mini")
    # gpt_response = gpt_client.Think([{"role": "user", "content": "Say YYJ"}])
    # print("GPT 最终答案：", gpt_response)

    # # LLaMA 示例
    # llama_client = LlamaClient(model_name="llama-4-scout-17b-16e-instruct")
    # llama_response = llama_client.Think([{"role": "user", "content": "你能用？"}])
    # print("LLaMA 最终答案：", llama_response)
