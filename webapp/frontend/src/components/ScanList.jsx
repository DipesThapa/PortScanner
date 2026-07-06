import { useCallback, useEffect, useRef, useState } from "react";
import PropTypes from "prop-types";

const statusColor = (status) => {
  switch (status) {
    case "completed":
      return "badge-success";
    case "running":
      return "badge-info";
    case "failed":
      return "badge-error";
    default:
      return "badge-muted";
  }
};

const PAGE_SIZE = 4;

function ScanList({ scans, selectedId, onSelect, loading, onDelete }) {
  const listRef = useRef(null);
  const [scrollMeta, setScrollMeta] = useState({
    canPrev: false,
    canNext: false,
    page: 1,
    totalPages: 1,
    rangeStart: 0,
    rangeEnd: 0,
  });

  const calculateMeta = useCallback(() => {
    const el = listRef.current;
    if (!el) {
      setScrollMeta((prev) => ({ ...prev, canPrev: false, canNext: false, page: 1, totalPages: 1, rangeStart: 0, rangeEnd: 0 }));
      return;
    }
    const { scrollTop, scrollHeight, clientHeight } = el;
    const canPrev = scrollTop > 4;
    const canNext = scrollTop + clientHeight < scrollHeight - 4;
    let totalPages = Math.max(1, Math.ceil(scans.length / PAGE_SIZE));

    let rangeStart = 0;
    let rangeEnd = 0;
    let page = 1;

    if (scans.length > 0) {
      const firstItem = el.firstElementChild;
      const styles = window.getComputedStyle(el);
      const gap = parseFloat(styles.rowGap || styles.gap || "0");
      let itemHeight = firstItem ? firstItem.getBoundingClientRect().height : 0;
      if (itemHeight === 0) {
        itemHeight = clientHeight / PAGE_SIZE;
      }
      const effectiveHeight = itemHeight + gap;
      const firstVisibleIndex = effectiveHeight > 0 ? Math.floor(scrollTop / effectiveHeight) : 0;
      rangeStart = firstVisibleIndex + 1;
      rangeEnd = Math.min(rangeStart + PAGE_SIZE - 1, scans.length);
      page = Math.floor((rangeStart - 1) / PAGE_SIZE) + 1;
    }

    if (isNaN(page) || page < 1) page = 1;
    if (isNaN(totalPages) || totalPages < 1) totalPages = 1;

    setScrollMeta({ canPrev, canNext, page, totalPages, rangeStart, rangeEnd });
  }, [scans.length]);

  const scrollByPage = useCallback(
    (direction) => {
      const el = listRef.current;
      if (!el) return;
      const firstItem = el.firstElementChild;
      const styles = window.getComputedStyle(el);
      const gap = parseFloat(styles.rowGap || styles.gap || "0");
      let step = el.clientHeight;
      if (firstItem) {
        const itemHeight = firstItem.getBoundingClientRect().height + gap;
        step = Math.max(itemHeight * PAGE_SIZE, 1);
      }
      el.scrollBy({ top: direction * step, behavior: "smooth" });
      window.requestAnimationFrame(() => {
        setTimeout(calculateMeta, 180);
      });
    },
    [calculateMeta],
  );

  useEffect(() => {
    calculateMeta();
  }, [calculateMeta, scans.length]);

  useEffect(() => {
    const el = listRef.current;
    if (!el) return;
    const handle = () => calculateMeta();
    el.addEventListener("scroll", handle);
    return () => {
      el.removeEventListener("scroll", handle);
    };
  }, [calculateMeta]);

  useEffect(() => {
    if (!selectedId) return;
    const el = listRef.current;
    if (!el) return;
    const target = el.querySelector(`[data-job-id="${selectedId}"]`);
    if (!target) return;
    const containerRect = el.getBoundingClientRect();
    const targetRect = target.getBoundingClientRect();
    if (targetRect.top < containerRect.top) {
      el.scrollBy({ top: targetRect.top - containerRect.top - 8, behavior: "smooth" });
    } else if (targetRect.bottom > containerRect.bottom) {
      el.scrollBy({ top: targetRect.bottom - containerRect.bottom + 8, behavior: "smooth" });
    }
    window.requestAnimationFrame(() => {
      setTimeout(calculateMeta, 160);
    });
  }, [calculateMeta, selectedId]);

  return (
    <div className="panel scan-list-panel">
      <div className="panel-header">
        <h2>Scan Jobs</h2>
      </div>
      <div className="panel-body">
        {loading && <p className="muted">Refreshing…</p>}
        {!loading && scans.length === 0 && <p>No scans yet. Submit a new job.</p>}
        {scrollMeta.rangeEnd > 0 && (
          <p className="muted range-indicator">
            Showing {scrollMeta.rangeStart}-{scrollMeta.rangeEnd} of {scans.length}
          </p>
        )}
        <ul className="scan-list" ref={listRef}>
          {scans.map((scan, index) => (
            <li key={scan.job_id} className={scan.job_id === selectedId ? "active" : ""}>
              <div className="list-item-row" data-job-id={scan.job_id} onClick={() => onSelect(scan.job_id)}>
                <div style={{ display: 'flex', alignItems: 'center', flex: 1, overflow: 'hidden' }}>
                  <span className="list-index">{index + 1}.</span>
                  <span className={`badge ${statusColor(scan.status)}`}>{scan.status}</span>
                  <span className="job-id">{scan.job_id}</span>
                </div>
                {onDelete && (
                  <button
                    className="btn-icon list-delete-btn"
                    onClick={(e) => { e.stopPropagation(); onDelete(scan.job_id); }}
                    title="Delete Scan"
                    style={{ marginLeft: '8px', padding: '4px', opacity: 0.7 }}
                  >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>
                  </button>
                )}
              </div>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

ScanList.propTypes = {
  scans: PropTypes.arrayOf(PropTypes.object).isRequired,
  selectedId: PropTypes.string,
  onSelect: PropTypes.func.isRequired,
  loading: PropTypes.bool,
  onDelete: PropTypes.func,
};

ScanList.defaultProps = {
  selectedId: null,
  loading: false,
  onDelete: null,
};

export default ScanList;
