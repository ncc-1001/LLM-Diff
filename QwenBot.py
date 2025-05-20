from dotenv import dotenv_values
config = dotenv_values('.qwenenv')
from openai import OpenAI
from openai import OpenAIError
import json
import os
import time
import logging

# 配置日志记录
logging.basicConfig(
    filename='log_positioning.log',  # 日志文件名
    level=logging.INFO,              # 日志级别
    format='%(asctime)s - %(levelname)s - %(message)s',  # 日志格式
    datefmt='%Y-%m-%d %H:%M:%S',     # 日期时间格式
    filemode='w'                     # 使用 'w' 模式覆盖旧日志
)

logger = logging.getLogger()

class QwenBot:
    def __init__(self):
        self.client = OpenAI(
            api_key="sk-e90ea09fa3e14c15990b40cccccccccc",  # use your api_key
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",  # base_url
        )

    def send_message(self, content, max_retries=3):
        retries = 0
        while retries < max_retries:
            try:
                completion = self.client.chat.completions.create(
                    # model="gpt-4o-mini",
                    model="qwen-plus",
                    messages=[
                        {'role': 'system', 'content': 'You are a helpful assistant.'},
                        {'role': 'user', 'content': content}
                    ],
                    temperature=0.2,
                    top_p=0.8
                )

                result_dict = json.loads(completion.model_dump_json())
                response_content = result_dict.get('choices', [{}])[0].get('message', {}).get('content', '')
                
                logger.info(f"Response Content:\n{response_content}")
                return result_dict

            except OpenAIError as e:   # 捕获通用 OpenAI 错误
                logger.warning(f"⚠️ OpenAI服务器错误，第{retries+1}次重试中，错误：{e}")
                retries += 1
                time.sleep(2)

            except Exception as e:
                logger.error(f"❌ 其他未知错误: {e}")
                raise e

        raise Exception("超过最大重试次数，发送失败。")

    def multi_round_test(self):
        while True:
            input_value = input("请输入问题（输入'quit'退出）: ")
            if input_value.lower() == 'quit':
                break
            self.send_message(input_value)

if __name__ == '__main__':
    bot = QwenBot()
    bot.multi_round_test()
