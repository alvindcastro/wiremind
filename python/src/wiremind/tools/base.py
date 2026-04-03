from typing import Any, Callable, Dict, List, Optional, Type
from pydantic import BaseModel, Field
import functools
import inspect

class WiremindTool:
    """
    Standardized decorator for Wiremind AI tools.
    Inspired by LangChain's tool decorator but simplified for our forensics needs.
    """
    def __init__(
        self,
        name: str,
        description: str,
        args_schema: Optional[Type[BaseModel]] = None,
    ):
        self.name = name
        self.description = description
        self.args_schema = args_schema

    def __call__(self, func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            return await func(*args, **kwargs)
        
        wrapper._is_wiremind_tool = True
        wrapper.name = self.name
        wrapper.description = self.description
        wrapper.args_schema = self.args_schema
        return wrapper

def is_tool(obj: Any) -> bool:
    """Checks if an object is a decorated WiremindTool."""
    return getattr(obj, "_is_wiremind_tool", False)

class ToolRegistry:
    """Registry to keep track of available tools for agents."""
    def __init__(self):
        self._tools: Dict[str, Callable] = {}

    def register(self, tool: Callable):
        if not is_tool(tool):
            raise ValueError(f"Object {tool} is not a WiremindTool")
        self._tools[tool.name] = tool

    def get_tool(self, name: str) -> Optional[Callable]:
        return self._tools.get(name)

    def list_tools(self) -> List[Callable]:
        return list(self._tools.values())
