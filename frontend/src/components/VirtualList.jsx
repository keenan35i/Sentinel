import React, { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';

function defaultGetItemKey(item, index) {
  return item?.finding_id || item?.id || item?.path || item?.key || `${index}`;
}

export default function VirtualList({
  items,
  estimatedItemHeight = 120,
  overscan = 6,
  maxHeight = 520,
  renderItem,
  className = '',
  itemClassName = '',
  getItemKey = defaultGetItemKey,
}) {
  const sizeMapRef = useRef(new Map());
  const [scrollTop, setScrollTop] = useState(0);
  const [version, setVersion] = useState(0);
  const viewportHeight = maxHeight;

  useEffect(() => {
    const activeKeys = new Set(items.map((item, index) => getItemKey(item, index)));
    let changed = false;
    Array.from(sizeMapRef.current.keys()).forEach((key) => {
      if (!activeKeys.has(key)) {
        sizeMapRef.current.delete(key);
        changed = true;
      }
    });
    if (changed) setVersion((value) => value + 1);
  }, [items, getItemKey]);

  const measurements = useMemo(() => {
    const offsets = new Array(items.length);
    let total = 0;

    for (let index = 0; index < items.length; index += 1) {
      offsets[index] = total;
      const key = getItemKey(items[index], index);
      total += sizeMapRef.current.get(key) || estimatedItemHeight;
    }

    return { offsets, totalHeight: total };
  }, [items, estimatedItemHeight, version, getItemKey]);

  const startIndex = useMemo(() => {
    const { offsets } = measurements;
    let low = 0;
    let high = offsets.length - 1;
    let answer = 0;

    while (low <= high) {
      const mid = Math.floor((low + high) / 2);
      if (offsets[mid] <= scrollTop) {
        answer = mid;
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }

    return Math.max(0, answer - overscan);
  }, [measurements, overscan, scrollTop]);

  const endIndex = useMemo(() => {
    const target = scrollTop + viewportHeight;
    const { offsets } = measurements;
    let low = 0;
    let high = offsets.length - 1;
    let answer = offsets.length - 1;

    while (low <= high) {
      const mid = Math.floor((low + high) / 2);
      if (offsets[mid] < target) {
        low = mid + 1;
      } else {
        answer = mid;
        high = mid - 1;
      }
    }

    return Math.min(items.length, answer + overscan + 1);
  }, [items.length, measurements, overscan, scrollTop, viewportHeight]);

  const visibleItems = useMemo(() => items.slice(startIndex, endIndex), [items, startIndex, endIndex]);

  return (
    <div
      className={`virtual-list ${className}`.trim()}
      style={{ maxHeight, overflow: 'auto' }}
      onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
    >
      <div className="virtual-inner" style={{ height: measurements.totalHeight || 0 }}>
        {visibleItems.map((item, localIndex) => {
          const actualIndex = startIndex + localIndex;
          const key = getItemKey(item, actualIndex);
          const top = measurements.offsets[actualIndex] || 0;

          return (
            <MeasuredRow
              key={key}
              itemKey={key}
              top={top}
              className={itemClassName}
              onHeight={(height) => {
                const current = sizeMapRef.current.get(key);
                if (current !== height) {
                  sizeMapRef.current.set(key, height);
                  setVersion((value) => value + 1);
                }
              }}
            >
              {renderItem(item, actualIndex)}
            </MeasuredRow>
          );
        })}
      </div>
    </div>
  );
}

function MeasuredRow({ itemKey, top, className, onHeight, children }) {
  const rowRef = useRef(null);

  useLayoutEffect(() => {
    const node = rowRef.current;
    if (!node) return undefined;

    const update = () => {
      const nextHeight = Math.ceil(node.getBoundingClientRect().height);
      if (nextHeight > 0) onHeight(nextHeight);
    };

    update();
    const observer = new ResizeObserver(update);
    observer.observe(node);
    return () => observer.disconnect();
  }, [itemKey, onHeight]);

  return (
    <div
      ref={rowRef}
      className={className}
      style={{
        position: 'absolute',
        top,
        left: 0,
        right: 0,
      }}
    >
      {children}
    </div>
  );
}
