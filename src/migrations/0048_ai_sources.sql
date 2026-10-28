-- AI as a beat of its own (28 October 2026): frontier labs, local models, the research, the
-- press that covers it and the communities that talk about it. Each feed answered when checked
-- that day (Reddit's throttled with 429 between quick checks, as Reddit does; the adapter spaces
-- its requests). They come into the News like any source; `topic` marks them as AI so the News
-- page can show them as a section, or leave them out for a reader who would rather it did.
-- A story from any other source counts as AI when its headline says so (src/topics.ts).
ALTER TABLE sources ADD COLUMN topic TEXT;

INSERT OR IGNORE INTO sources (id, name, kind, group_name, url, format, schedule, enabled, licence, attribution, notes, topic) VALUES
('openai-news',        'OpenAI news',                       'article', 'news', 'https://openai.com/news/rss.xml', 'rss', 'daily', 1, NULL, 'OpenAI', 'Model releases, research and policy from OpenAI. A large feed (about 800 KB); daily.', 'ai'),
('deepmind-blog',      'Google DeepMind blog',              'article', 'news', 'https://deepmind.google/blog/rss.xml', 'rss', 'daily', 1, NULL, 'Google DeepMind', NULL, 'ai'),
('google-ai-blog',     'Google · AI',                       'article', 'news', 'https://blog.google/technology/ai/rss/', 'rss', 'daily', 1, NULL, 'Google', 'Gemini and Google''s AI products.', 'ai'),
('huggingface-blog',   'Hugging Face blog',                 'article', 'news', 'https://huggingface.co/blog/feed.xml', 'rss', 'daily', 1, NULL, 'Hugging Face', 'Open models, datasets and the tooling around them.', 'ai'),
('ollama-blog',        'Ollama blog',                       'article', 'news', 'https://ollama.com/blog/rss.xml', 'rss', 'daily', 1, NULL, 'Ollama', 'Local models: what runs, and on what.', 'ai'),
('nvidia-genai',       'NVIDIA · generative AI',            'article', 'news', 'https://blogs.nvidia.com/blog/category/generative-ai/feed/', 'rss', 'daily', 1, NULL, 'NVIDIA', NULL, 'ai'),
('simonwillison',      'Simon Willison',                    'article', 'news', 'https://simonwillison.net/atom/everything/', 'atom', 'hourly', 1, NULL, 'Simon Willison', 'LLMs in practice, prompt injection, and the tools; often first to explain a release.', 'ai'),
('embrace-the-red',    'Embrace The Red',                   'article', 'news', 'https://embracethered.com/blog/index.xml', 'rss', 'daily', 1, NULL, 'Johann Rehberger', 'Attacks on AI systems: prompt injection, data exfiltration through agents.', 'ai'),
('the-decoder',        'The Decoder',                       'article', 'news', 'https://the-decoder.com/feed/', 'rss', 'hourly', 1, NULL, 'The Decoder', 'AI news, daily.', 'ai'),
('mit-tr-ai',          'MIT Technology Review · AI',        'article', 'news', 'https://www.technologyreview.com/topic/artificial-intelligence/feed', 'rss', 'daily', 1, NULL, 'MIT Technology Review', NULL, 'ai'),
('verge-ai',           'The Verge · AI',                    'article', 'news', 'https://www.theverge.com/rss/ai-artificial-intelligence/index.xml', 'atom', 'hourly', 1, NULL, 'The Verge', NULL, 'ai'),
('ars-ai',             'Ars Technica · AI',                 'article', 'news', 'https://arstechnica.com/ai/feed/', 'rss', 'hourly', 1, NULL, 'Ars Technica', NULL, 'ai'),
('importai',           'Import AI',                         'article', 'news', 'https://importai.substack.com/feed', 'rss', 'weekly', 1, NULL, 'Jack Clark', 'A weekly newsletter on AI research and policy.', 'ai'),
('latent-space',       'Latent Space',                      'article', 'news', 'https://www.latent.space/feed', 'rss', 'weekly', 1, NULL, 'Latent Space', 'AI engineering; a large feed (about 1.4 MB), read weekly.', 'ai'),
('interconnects',      'Interconnects',                     'article', 'news', 'https://www.interconnects.ai/feed', 'rss', 'weekly', 1, NULL, 'Nathan Lambert', 'Open models and post-training, weekly.', 'ai'),
('hn-ai',              'Hacker News (AI)',                  'article', 'news', 'https://hn.algolia.com/api/v1/search_by_date?tags=story&query=AI&numericFilters=points%3E100&hitsPerPage=50', 'json', 'hourly', 1, NULL, 'Hacker News', 'Stories naming AI that reached a hundred points.', 'ai'),
('reddit-localllama',      'r/LocalLLaMA',      'article', 'news', 'https://www.reddit.com/r/LocalLLaMA/new.rss?limit=50',      'atom', 'hourly', 1, 'Reddit API terms; personal, identified use', NULL, 'Running models locally.', 'ai'),
('reddit-ollama',          'r/ollama',          'article', 'news', 'https://www.reddit.com/r/ollama/new.rss?limit=50',          'atom', 'hourly', 1, 'Reddit API terms; personal, identified use', NULL, NULL, 'ai'),
('reddit-stablediffusion', 'r/StableDiffusion', 'article', 'news', 'https://www.reddit.com/r/StableDiffusion/new.rss?limit=50', 'atom', 'hourly', 1, 'Reddit API terms; personal, identified use', NULL, 'Local image models.', 'ai'),
('reddit-machinelearning', 'r/MachineLearning', 'article', 'news', 'https://www.reddit.com/r/MachineLearning/new.rss?limit=50', 'atom', 'hourly', 1, 'Reddit API terms; personal, identified use', NULL, NULL, 'ai'),
('reddit-artificial',      'r/artificial',      'article', 'news', 'https://www.reddit.com/r/artificial/new.rss?limit=50',      'atom', 'hourly', 1, 'Reddit API terms; personal, identified use', NULL, NULL, 'ai'),
('reddit-openai',          'r/OpenAI',          'article', 'news', 'https://www.reddit.com/r/OpenAI/new.rss?limit=50',          'atom', 'hourly', 1, 'Reddit API terms; personal, identified use', NULL, NULL, 'ai'),
('reddit-claudeai',        'r/ClaudeAI',        'article', 'news', 'https://www.reddit.com/r/ClaudeAI/new.rss?limit=50',        'atom', 'hourly', 1, 'Reddit API terms; personal, identified use', NULL, NULL, 'ai'),
('reddit-singularity',     'r/singularity',     'article', 'news', 'https://www.reddit.com/r/singularity/new.rss?limit=50',     'atom', 'hourly', 1, 'Reddit API terms; personal, identified use', NULL, 'Frontier models and the talk about them; loud.', 'ai');
