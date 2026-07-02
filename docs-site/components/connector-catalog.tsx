import Link from 'next/link';
import { ArrowRight } from 'lucide-react';
import { ConnectorBrand } from '@/components/connector-brand';
import matrix from '@/data/capability-matrix.json';

export function ConnectorCatalog() {
  return (
    <div className="connector-catalog not-prose">
      {matrix.connectors.map((connector) => {
        const { id } = connector;
        return (
          <Link className="connector-catalog-item" href={`/docs/connectors/${id}`} key={id}>
            <ConnectorBrand id={id} />
            <span className="connector-catalog-copy">
              <strong>{connector.label}</strong>
              <span>{connector.summary}</span>
            </span>
            <ArrowRight aria-hidden />
          </Link>
        );
      })}
    </div>
  );
}
