import { OS_IDS, supportMatrix } from '@/data/support-matrix';
import styles from './support-matrix.module.css';

// Operating systems and architectures, and where each edition was verified.
export function PlatformTable() {
  return (
    <div className={`not-prose ${styles.matrix}`}>
      <div className={styles.tableWrapAlways}>
        <table className={styles.table}>
          <caption className={styles.srOnly}>Platforms and where each edition was verified</caption>
          <thead>
            <tr>
              <th scope="col">OS</th>
              <th scope="col">Architectures</th>
              <th scope="col">Open source verified on</th>
              <th scope="col">Enterprise verified on</th>
            </tr>
          </thead>
          <tbody>
            {OS_IDS.map((os) => {
              const p = supportMatrix.platforms[os];
              return (
                <tr key={os}>
                  <th scope="row">{p.label}</th>
                  <td>{p.arch}</td>
                  <td>{p.certifiedOn}</td>
                  <td>{p.enterpriseCertifiedOn}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
