/**
 * AI as a beat across the News. A story is about AI when its source is one of the AI sources
 * (`sources.topic = 'ai'`, migration 0048) or when its headline uses one of these words — the
 * security press writes about prompt injection and agents as often as the AI press does, and those
 * stories belong in both places. Headlines only, as with the platforms: a long post that mentions
 * ChatGPT once is not an AI story. Matched as whole words through the items' FTS index.
 */
export const aiTerms: readonly string[] = [
  "ai",
  "genai",
  "llm",
  "llms",
  "chatgpt",
  "openai",
  "anthropic",
  "claude",
  "gemini",
  "deepmind",
  "copilot",
  "gpt",
  "llama",
  "mistral",
  "deepseek",
  "qwen",
  "ollama",
  "hugging face",
  "huggingface",
  "vllm",
  "langchain",
  "prompt injection",
  "machine learning",
  "deep learning",
  "neural network",
  "deepfake",
  "deepfakes",
  "agentic",
  "ai agent",
  "ai agents",
  "model context protocol",
  "mcp",
  "frontier model",
  "foundation model",
  "stable diffusion",
  "midjourney",
  "grok",
];

/** The terms as an FTS5 query on the headline column: each quoted, any of them. */
export const aiHeadlineQuery = `title : (${aiTerms.map((t) => `"${t}"`).join(" OR ")})`;

/** An item is about AI: its source's topic, or its headline. Over `items i`; takes `aiHeadlineQuery` as its one parameter. */
export const aiItemSql = "(i.source_id IN (SELECT id FROM sources WHERE topic = 'ai') OR i.id IN (SELECT rowid FROM items_fts WHERE items_fts MATCH ?))";
