// Semgrep rule tests (React). Lines after a "rule id" annotation must match; lines after an "ok" annotation must not.
import DOMPurify from "dompurify";

export function Comment({ html }) {
  // ruleid: aca-js-react-dangerously-set-inner-html
  const raw = <div dangerouslySetInnerHTML={{ __html: html }} />;
  // ok: aca-js-react-dangerously-set-inner-html
  const clean = <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
  return <section>{raw}{clean}</section>;
}
