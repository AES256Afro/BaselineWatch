import { html } from "../../html.ts";
import type { GuideArticle } from "../guide-article.ts";

/**
 * October 2026: two critical flaws in PHP *applications* broke on the same day and the News
 * started calling them "the PHP hack", which sends people to check `php -v` and find nothing. The
 * article exists to correct that and to say what can honestly be done while no fix is published.
 * It carries no version numbers of its own: the severities, the exploitation signals and whether a
 * patch exists are read from this instance's table by the renderer on every request.
 */
export const phpApplications: GuideArticle = {
  slug: "php-applications",
  title: "The “PHP hack”: it is not PHP",
  description: "Two critical flaws in Joomla and WordPress extensions, what they are, how to tell whether they affect you, and what to do while no patch exists.",
  written: "2026-10-22",
  cves: ["CVE-2026-102785", "CVE-2026-112832"],
  standfirst: html`
    Two critical flaws in widely installed content-management extensions were published on
    22 October 2026, and the shorthand going round for them is “the PHP hack”. That name is
    misleading in a way that costs people time: neither is a flaw in PHP. Both are flaws in
    software <i>written in</i> PHP, running inside Joomla and WordPress, and upgrading PHP fixes
    neither of them.`,
  sections: [
    {
      id: "not-php",
      heading: "It is not a flaw in PHP",
      body: html`
        <p>
          PHP is the language these extensions are written in, not the thing that is broken. A
          server running the newest PHP release is exactly as exposed as one running an old release,
          because the flaw is in the extension's own code. Checking <code>php -v</code> will tell you
          nothing about either of these, and neither will upgrading it.
        </p>
        <p>
          What matters is the <b>extension list of your content-management system</b>: which plugins
          and templates are installed, at which versions. That is a different screen in a different
          admin panel, and it is the one to open.
        </p>`,
    },
    {
      id: "the-two",
      heading: "What the two flaws are",
      body: html`
        <p>
          <b>YOOtheme Pro, a Joomla template</b>. Its image-transformation handler is reachable
          without signing in, and requests to it are signed. The published description says the
          signature does not fully bind the normalised image operations and the output destination —
          so a signature that appears in an ordinary public image URL on the site can be reused with
          other operations attached. The result is remote code execution with no account and no
          interaction from anybody.
        </p>
        <p>
          <b>Rootblox, a WordPress plugin</b>. A filename that a request can influence reaches a PHP
          <code>include</code> or <code>require</code> statement, which is the file-inclusion class
          of flaw: the program is persuaded to execute a file the author did not intend it to.
        </p>
        <p class="small">
          Both descriptions above are the published CVE records', which this instance reads from NVD;
          the CVE pages linked in the table quote them in full. The first is scored 10.0 — as high as
          the scale goes — and the severity vector recorded for it already carries an exploit-maturity
          value of <i>attacked</i>, meaning the scorer believed it was being used in the wild at the
          time they scored it.
        </p>`,
    },
    {
      id: "affected",
      heading: "Whether this affects you",
      body: html`
        <p>
          The affected ranges, as the records state them: <b>YOOtheme Pro 5.0.0 to 5.0.52</b> on
          Joomla, and <b>Rootblox up to and including its 1.x line</b> on WordPress. Where to look:
        </p>
        <ul>
          <li><b>Joomla</b>: the administrator panel, System → Manage → Extensions, and the template's own version.</li>
          <li><b>WordPress</b>: the administrator panel, Plugins → Installed Plugins.</li>
        </ul>
        <p class="small">
          Affected ranges are the vendor's claim at the time of publication and they are frequently
          revised upward once someone looks harder. Treat “my version is one below the range” as a
          reason to watch the advisory, not as a clean bill of health. If you run neither extension,
          neither of these is yours — though the file-inclusion class in the second is common enough
          that it is worth knowing by shape.
        </p>`,
    },
    {
      id: "no-fix",
      heading: "There may be nothing to patch to yet",
      body: html`
        <p>
          The <b>Fix</b> column in the table above is not prose — it is what this instance actually
          holds: patch references, vendor advisories, fixed package versions and any CISA action. If
          it says nothing is published, then as far as the sources this site reads are concerned,
          there is no fixed version to move to. That column changes on its own when one appears, so
          the page is worth re-reading rather than trusting this paragraph.
        </p>
        <p>
          While that is the case, patching is not among your options and the honest list is shorter
          than people would like:
        </p>
        <ul>
          <li>
            <b>Decide whether the thing needs to be reachable from the internet at all.</b> The most
            effective answer to an unauthenticated remote flaw is usually that the component is not
            reachable by unauthenticated strangers. That may mean taking a site offline, and that is
            a real cost — weigh it honestly rather than dismissing it.
          </li>
          <li>
            <b>Block at the edge only on the vendor's or your host's published rule.</b> A filter you
            invent for a flaw whose mechanics you are inferring tends to stop the example and not the
            class. Where your hosting provider or the vendor publishes a rule, that is the one to use.
          </li>
          <li>
            <b>Have a backup you have restored from, not merely taken.</b> An untested backup is a
            hope. This applies before you need it, which is now.
          </li>
          <li>
            <b>Assume reach, not just risk.</b> Where a flaw is being exploited and your installation
            was exposed, the question is not only “can I be attacked” but “was I already”. Plan for
            looking, and for what you would do if the answer is yes — that is a different and slower
            piece of work than patching, and it is better begun early.
          </li>
        </ul>`,
    },
    {
      id: "why",
      heading: "Why a signed URL gets reused",
      body: html`
        <p>
          The YOOtheme flaw is worth understanding past its own CVE, because the shape recurs. A
          signed URL is a <i>capability</i>: a token that says the bearer may ask for this. The
          signature's job is to cover everything it authorises. When it covers some parameters and
          not others, the ones left out are free for anybody holding a signature — and a signature
          that appears in a public image URL on the site is held by everybody.
        </p>
        <p>
          This is a design flaw rather than a typo, which is why it survives review: each piece looks
          correct in isolation. The general rule it breaks — that what a request is permitted to do
          must be derived from everything the request says, not from part of it — is the kind of
          requirement control catalogues state and configuration settings cannot enforce for you.
          <a href="/learn">Learn</a> is where those catalogues come from, and
          <a href="/controls">Controls</a> searches them a rule at a time.
        </p>`,
    },
    {
      id: "limits",
      heading: "What this page cannot tell you",
      body: html`
        <p class="small">
          It cannot tell you whether you run either extension — no web page can see your servers, and
          this site probes nothing it was not asked to. It cannot tell you whether you have been
          compromised; the absence of a KEV entry or an EPSS score means those sources have not
          spoken yet, not that you are safe. And it is not legal or contractual advice about
          disclosure obligations, which differ by where you are and who your data belongs to. What it
          does carry is the published record, kept current:
          <a href="/vulnerabilities?q=php">every PHP-related CVE this instance has seen</a>, and
          <a href="/search?q=php">what the sources have said</a>.
        </p>`,
    },
  ],
};
