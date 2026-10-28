import json
import logging
import os
from typing import Dict, List, Optional, Union

from openai import OpenAI

from mem0.configs.llms.base import BaseLlmConfig
from mem0.configs.llms.openai import OpenAIConfig
from mem0.llms.base import LLMBase
from mem0.memory.utils import extract_json


class OpenAILLM(LLMBase):
    def __init__(self, config: Optional[Union[BaseLlmConfig, OpenAIConfig, Dict]] = None):
        # Convert to OpenAIConfig if needed
        if config is None:
            config = OpenAIConfig()
        elif isinstance(config, dict):
            config = OpenAIConfig(**config)
        elif isinstance(config, BaseLlmConfig) and not isinstance(config, OpenAIConfig):
            # Convert BaseLlmConfig to OpenAIConfig
            config = OpenAIConfig(
                model=config.model,
                temperature=config.temperature,
                api_key=config.api_key,
                max_tokens=config.max_tokens,
                top_p=config.top_p,
                top_k=config.top_k,
                enable_vision=config.enable_vision,
                vision_details=config.vision_details,
                reasoning_effort=getattr(config, "reasoning_effort", None),
                http_client_proxies=config.http_client_proxies,
                is_reasoning_model=getattr(config, "is_reasoning_model", None),
            )

        super().__init__(config)

        if not self.config.model:
            self.config.model = "gpt-5-mini"

        if os.environ.get("OPENROUTER_API_KEY"):  # Use OpenRouter
            self.client = OpenAI(
                api_key=os.environ.get("OPENROUTER_API_KEY"),
                base_url=self.config.openrouter_base_url
                or os.getenv("OPENROUTER_API_BASE")
                or "https://openrouter.ai/api/v1",
            )
        else:
            api_key = self.config.api_key or os.getenv("OPENAI_API_KEY")
            base_url = self.config.openai_base_url or os.getenv("OPENAI_BASE_URL") or "https://api.openai.com/v1"

            self.client = OpenAI(api_key=api_key, base_url=base_url)

    def _parse_response(self, response, tools):
        """
        Process the response based on whether tools are used or not.

        Args:
            response: The raw response from API.
            tools: The list of tools provided in the request.

        Returns:
            str or dict: The processed response.
        """
        if tools:
            processed_response = {
                "content": response.choices[0].message.content,
                "tool_calls": [],
            }

            if response.choices[0].message.tool_calls:
                for tool_call in response.choices[0].message.tool_calls:
                    processed_response["tool_calls"].append(
                        {
                            "name": tool_call.function.name,
                            "arguments": json.loads(extract_json(tool_call.function.arguments)),
                        }
                    )

            return processed_response
        else:
            return response.choices[0].message.content

    def _generate_responses_with_tools(self, messages, response_format, tools, tool_choice, kwargs):
        # Responses and Chat Completions use different function schemas.
        if kwargs:
            raise ValueError("GPT-6.1 tool calls do not support additional Chat Completions parameters")
        if any(tool.get("type") != "function" for tool in tools):
            raise ValueError("GPT-6.1 tool calls support function tools only")
        if any(
            not isinstance(message.get("content"), str) or message.get("role") not in {"system", "user", "assistant"}
            for message in messages
        ):
            raise ValueError("GPT-6.1 tool calls currently require text-only messages")
        converted_tools = []
        for tool in tools:
            function = dict(tool["function"])
            function.setdefault("strict", False)
            converted_tools.append({"type": "function", **function})
        params = {
            "model": self.config.model,
            "input": messages,
            "tools": converted_tools,
            "tool_choice": tool_choice,
            "max_output_tokens": self.config.max_tokens,
            "store": self.config.store if self.config.store is not None else False,
        }
        if isinstance(tool_choice, dict):
            params["tool_choice"] = {"type": "function", "name": tool_choice["function"]["name"]}
        if self.config.reasoning_effort:
            params["reasoning"] = {"effort": self.config.reasoning_effort}
        if response_format:
            if response_format.get("type") == "json_schema":
                params["text"] = {"format": {"type": "json_schema", **response_format["json_schema"]}}
            else:
                params["text"] = {"format": response_format}
        response = self.client.responses.create(**params)
        if getattr(response, "status", None) in {"incomplete", "failed"}:
            raise RuntimeError(f"OpenAI response was {response.status}")
        if any(part.type == "refusal" for item in response.output if item.type == "message" for part in item.content):
            raise RuntimeError("OpenAI refused the tool request")
        parsed = {
            "content": response.output_text or None,
            "tool_calls": [
                {"name": item.name, "arguments": json.loads(extract_json(item.arguments))}
                for item in response.output
                if item.type == "function_call"
            ],
        }
        if self.config.response_callback:
            try:
                self.config.response_callback(self, response, params)
            except Exception as e:
                logging.error(f"Error due to callback: {e}")
        return parsed

    def generate_response(
        self,
        messages: List[Dict[str, str]],
        response_format=None,
        tools: Optional[List[Dict]] = None,
        tool_choice: str = "auto",
        **kwargs,
    ):
        """
        Generate a JSON response based on the given messages using OpenAI.

        Args:
            messages (list): List of message dicts containing 'role' and 'content'.
            response_format (str or object, optional): Format of the response. Defaults to "text".
            tools (list, optional): List of tools that the model can call. Defaults to None.
            tool_choice (str, optional): Tool choice method. Defaults to "auto".
            **kwargs: Additional OpenAI-specific parameters.

        Returns:
            json: The generated response.
        """
        model_name = self.config.model.lower().rsplit("/", 1)[-1]
        gpt61_tool_model = any(
            model_name == name or model_name.startswith(name + "-") for name in ("gpt-6.1-sol", "gpt-6.1-terra")
        )
        if tools and gpt61_tool_model:
            return self._generate_responses_with_tools(messages, response_format, tools, tool_choice, kwargs)

        params = self._get_supported_params(messages=messages, **kwargs)
        if model_name == "gpt-6-luna" or model_name.startswith("gpt-6-luna-"):
            if tools and self.config.reasoning_effort not in (None, "none"):
                raise ValueError("GPT-6 Luna function calls require reasoning_effort='none'")
            if not self.config.reasoning_effort:
                params["reasoning_effort"] = "none"

        params.update(
            {
                "model": self.config.model,
                "messages": messages,
            }
        )

        if os.getenv("OPENROUTER_API_KEY"):
            openrouter_params = {}
            if self.config.models:
                openrouter_params["models"] = self.config.models
                openrouter_params["route"] = self.config.route
                params.pop("model")

            if self.config.site_url and self.config.app_name:
                extra_headers = {
                    "HTTP-Referer": self.config.site_url,
                    "X-Title": self.config.app_name,
                }
                openrouter_params["extra_headers"] = extra_headers

            params.update(**openrouter_params)

        else:
            # Only send OpenAI-specific parameters when the user has explicitly
            # configured them. OpenAI-compatible backends (Gemini, Groq, vLLM, etc.)
            # reject unknown fields, so `store` must be opt-in, not opt-out.
            if self.config.store is not None:
                params["store"] = self.config.store

        if response_format:
            params["response_format"] = response_format
        if tools:  # TODO: Remove tools if no issues found with new memory addition logic
            params["tools"] = tools
            params["tool_choice"] = tool_choice
        response = self.client.chat.completions.create(**params)
        parsed_response = self._parse_response(response, tools)
        if self.config.response_callback:
            try:
                self.config.response_callback(self, response, params)
            except Exception as e:
                # Log error but don't propagate
                logging.error(f"Error due to callback: {e}")
                pass
        return parsed_response
