import Link from 'next/link';
import { FEATURE_GROUPS, OS_IDS, supportMatrix, type FeatureRow } from '@/data/support-matrix';
import { MatrixFooter } from './matrix-footer';
import { StatusBadge } from './status-badge';
import styles from './support-matrix.module.css';

const OS_SHORT = { linux: 'Linux', macos: 'macOS', windows: 'Windows' } as const;

function FeatureLabel({ row }: { row: FeatureRow }) {
  return (
    <span className={styles.featureText}>
      <Link href={row.href} className={styles.featureName}>
        {row.label}
      </Link>
      {row.note ? <span className={styles.agentSub}>{row.note}</span> : null}
    </span>
  );
}

// Feature x edition: open source (per-user) and enterprise (standalone
// managed profile), each on Linux, macOS and Windows.
export function EditionMatrix() {
  const groups = FEATURE_GROUPS.map((group) => ({
    group,
    rows: supportMatrix.features.filter((row) => row.group === group),
  })).filter((g) => g.rows.length > 0);

  return (
    <div className={`not-prose ${styles.matrix}`}>
      <div className={styles.tableWrap}>
        <table className={`${styles.table} ${styles.editionTable}`}>
          <caption className={styles.srOnly}>DefenseClaw features by edition and operating system</caption>
          <colgroup>
            <col />
            <col span={3} />
            <col span={3} className={styles.entCols} />
          </colgroup>
          <thead>
            <tr>
              <th scope="col" rowSpan={2}>
                Feature
              </th>
              <th scope="colgroup" colSpan={3} className={styles.groupHead}>
                Open source
              </th>
              <th scope="colgroup" colSpan={3} className={`${styles.groupHead} ${styles.entStart}`}>
                Enterprise
              </th>
            </tr>
            <tr>
              {(['oss', 'enterprise'] as const).flatMap((edition) =>
                OS_IDS.map((os, i) => (
                  <th
                    key={`${edition}-${os}`}
                    scope="col"
                    className={`${styles.osHead} ${edition === 'enterprise' && i === 0 ? styles.entStart : ''}`}
                  >
                    {OS_SHORT[os]}
                  </th>
                )),
              )}
            </tr>
          </thead>
          {groups.map(({ group, rows }) => (
            <tbody key={group}>
              <tr className={styles.groupRow}>
                <th scope="colgroup" colSpan={7}>
                  {group}
                </th>
              </tr>
              {rows.map((row) => (
                <tr key={row.id}>
                  <th scope="row">
                    <FeatureLabel row={row} />
                  </th>
                  {OS_IDS.map((os) => (
                    <td key={`oss-${os}`}>
                      <StatusBadge status={row.oss[os]} compact />
                    </td>
                  ))}
                  {OS_IDS.map((os, i) => (
                    <td key={`ent-${os}`} className={i === 0 ? styles.entStart : undefined}>
                      <StatusBadge status={row.enterprise[os]} compact />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          ))}
        </table>
      </div>

      <div className={styles.cards}>
        {groups.map(({ group, rows }) => (
          <section key={group} aria-label={group}>
            <p className={styles.cardGroup}>{group}</p>
            <ul className={styles.cardList}>
              {rows.map((row) => (
                <li key={row.id} className={styles.card}>
                  <FeatureLabel row={row} />
                  <dl className={styles.editionRows}>
                    {(['oss', 'enterprise'] as const).map((edition) => (
                      <div key={edition} className={styles.editionRow}>
                        <dt>{edition === 'oss' ? 'Open source' : 'Enterprise'}</dt>
                        <dd>
                          {OS_IDS.map((os) => (
                            <span key={os} className={styles.osPair}>
                              <span className={styles.osPairLabel}>{OS_SHORT[os]}</span>
                              <StatusBadge status={row[edition][os]} compact />
                            </span>
                          ))}
                        </dd>
                      </div>
                    ))}
                  </dl>
                </li>
              ))}
            </ul>
          </section>
        ))}
      </div>
      <MatrixFooter />
    </div>
  );
}
