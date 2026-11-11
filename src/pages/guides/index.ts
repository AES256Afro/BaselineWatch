import type { GuideArticle } from "../guide-article.ts";
import { phpApplications } from "./php-applications.ts";

/**
 * The guide's articles, one module each. A slug is a permanent address once published, so renaming
 * one means leaving a redirect behind rather than editing this list.
 */
export const guideArticles: GuideArticle[] = [phpApplications];

export function guideBySlug(slug: string): GuideArticle | undefined {
  return guideArticles.find((a) => a.slug === slug);
}
