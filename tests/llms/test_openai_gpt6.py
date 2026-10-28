from types import SimpleNamespace
from unittest.mock import patch

import pytest

from mem0.configs.llms.openai import OpenAIConfig
from mem0.llms.openai import OpenAILLM


@pytest.mark.parametrize("model", ["gpt-6-luna", "gpt-6.1-terra", "gpt-6.1-sol"])
def test_gpt6_memory_extraction_uses_compatible_request(model):
    with patch("mem0.llms.openai.OpenAI") as client_class:
        client = client_class.return_value
        client.chat.completions.create.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"memory": []}'))]
        )
        llm = OpenAILLM(OpenAIConfig(model=model))
        result = llm.generate_response(
            [{"role": "user", "content": "Remember this"}], response_format={"type": "json_object"}
        )
        assert result == '{"memory": []}'
        request = client.chat.completions.create.call_args.kwargs
        assert "temperature" not in request
        assert "top_p" not in request
        assert "max_tokens" not in request
        assert request["response_format"] == {"type": "json_object"}
        if model == "gpt-6-luna":
            assert request["reasoning_effort"] == "none"


@pytest.mark.parametrize("model", ["gpt-6.1-terra", "gpt-6.1-sol"])
def test_gpt61_function_calling_uses_responses_api(model):
    tools = [
        {
            "type": "function",
            "function": {
                "name": "add_memory",
                "parameters": {"type": "object", "properties": {"text": {"type": "string"}}},
            },
        }
    ]
    with patch("mem0.llms.openai.OpenAI") as client_class:
        client = client_class.return_value
        client.responses.create.return_value = SimpleNamespace(
            output_text="",
            output=[SimpleNamespace(type="function_call", name="add_memory", arguments='{"text":"tea"}')],
        )
        llm = OpenAILLM(OpenAIConfig(model=model))
        result = llm.generate_response([{"role": "user", "content": "Remember tea"}], tools=tools)
        assert result == {"content": None, "tool_calls": [{"name": "add_memory", "arguments": {"text": "tea"}}]}
        params = client.responses.create.call_args.kwargs
        assert params["store"] is False
        assert params["tools"][0]["name"] == "add_memory"
        assert params["tools"][0]["strict"] is False
        client.chat.completions.create.assert_not_called()


def test_luna_tool_calls_reject_reasoning_effort_that_openai_does_not_support():
    with patch("mem0.llms.openai.OpenAI") as client_class:
        llm = OpenAILLM(OpenAIConfig(model="gpt-6-luna", reasoning_effort="medium"))
        with pytest.raises(ValueError, match="reasoning_effort"):
            llm.generate_response(
                [{"role": "user", "content": "Remember tea"}],
                tools=[{"type": "function", "function": {"name": "save"}}],
            )
        client_class.return_value.chat.completions.create.assert_not_called()


def test_gpt61_incomplete_tool_response_is_not_treated_as_success():
    with patch("mem0.llms.openai.OpenAI") as client_class:
        client_class.return_value.responses.create.return_value = SimpleNamespace(status="incomplete")
        llm = OpenAILLM(OpenAIConfig(model="gpt-6.1-sol"))
        with pytest.raises(RuntimeError, match="incomplete"):
            llm.generate_response(
                [{"role": "user", "content": "Remember tea"}],
                tools=[{"type": "function", "function": {"name": "save"}}],
            )


@pytest.mark.parametrize("model", ["gpt-6-luna", "gpt-6.1-terra", "gpt-6.1-sol"])
def test_memory_extraction_uses_selected_gpt6_model(model):
    from unittest.mock import MagicMock
    from mem0.memory.main import Memory

    with patch("mem0.llms.openai.OpenAI") as client_class:
        client = client_class.return_value
        client.chat.completions.create.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"memory": []}'))]
        )
        memory = object.__new__(Memory)
        memory.llm = OpenAILLM(OpenAIConfig(model=model))
        memory.db = MagicMock()
        memory.db.get_last_messages.return_value = []
        memory.embedding_model = MagicMock()
        memory.vector_store = MagicMock()
        memory.vector_store.search.return_value = []
        memory.custom_instructions = None
        result = memory._add_to_vector_store(
            messages=[{"role": "user", "content": "Hello"}],
            metadata={},
            filters={"user_id": "test-user"},
            infer=True,
        )
        assert result == []
        assert client.chat.completions.create.call_args.kwargs["model"] == model
        assert client.chat.completions.create.call_args.kwargs["response_format"] == {"type": "json_object"}


def test_gpt61_preserves_named_tool_choice_and_json_format():
    with patch("mem0.llms.openai.OpenAI") as client_class:
        client = client_class.return_value
        client.responses.create.return_value = SimpleNamespace(output_text="ok", output=[])
        llm = OpenAILLM(OpenAIConfig(model="gpt-6.1-sol", reasoning_effort="low"))
        tools = [{"type": "function", "function": {"name": "save", "parameters": {"type": "object"}}}]
        response = llm.generate_response(
            [{"role": "user", "content": "Save"}],
            tools=tools,
            tool_choice={"type": "function", "function": {"name": "save"}},
            response_format={"type": "json_object"},
        )
        request = client.responses.create.call_args.kwargs
        assert response == {"content": "ok", "tool_calls": []}
        assert request["tool_choice"] == {"type": "function", "name": "save"}
        assert request["text"] == {"format": {"type": "json_object"}}
        assert request["reasoning"] == {"effort": "low"}


def test_gpt61_unsupported_multimodal_tools_fail_before_request():
    with patch("mem0.llms.openai.OpenAI") as client_class:
        llm = OpenAILLM(OpenAIConfig(model="gpt-6.1-terra"))
        with pytest.raises(ValueError, match="text-only"):
            llm.generate_response(
                [
                    {
                        "role": "user",
                        "content": [{"type": "image_url", "image_url": {"url": "https://example.invalid/image"}}],
                    }
                ],
                tools=[{"type": "function", "function": {"name": "save"}}],
            )
        client_class.return_value.responses.create.assert_not_called()


def test_gpt61_function_call_refusal_is_not_a_success():
    with patch("mem0.llms.openai.OpenAI") as client_class:
        client_class.return_value.responses.create.return_value = SimpleNamespace(
            status="completed",
            output_text="",
            output=[
                SimpleNamespace(type="message", content=[SimpleNamespace(type="refusal", refusal="Unable to help")])
            ],
        )
        llm = OpenAILLM(OpenAIConfig(model="gpt-6.1-sol"))
        with pytest.raises(RuntimeError, match="refused"):
            llm.generate_response(
                [{"role": "user", "content": "Test"}], tools=[{"type": "function", "function": {"name": "save"}}]
            )
