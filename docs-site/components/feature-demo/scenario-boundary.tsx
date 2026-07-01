import { Check, Minus } from 'lucide-react';

export function ScenarioBoundary({
  did,
  didNot,
}: {
  did: string[];
  didNot: string[];
}) {
  return (
    <details className="scenario-boundary">
      <summary>What DefenseClaw did — and did not do</summary>
      <div className="scenario-boundary-grid">
        <section aria-labelledby="scenario-did-heading">
          <h3 id="scenario-did-heading">What it did</h3>
          <ul>{did.map((item) => <li key={item}><Check aria-hidden />{item}</li>)}</ul>
        </section>
        <section aria-labelledby="scenario-did-not-heading">
          <h3 id="scenario-did-not-heading">What it did not do</h3>
          <ul>{didNot.map((item) => <li key={item}><Minus aria-hidden />{item}</li>)}</ul>
        </section>
      </div>
    </details>
  );
}
