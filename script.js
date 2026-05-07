import { exampleMaps, exampleSmaps} from './exampleValues.js';
(
    function () {
    const canvas = document.getElementById('canvas');
    const mapsInput = document.getElementById('mapsInput');
    const smapsInput = document.getElementById('smapsInput');
    const renderBtn = document.getElementById('renderBtn');
    const compressBtn = document.getElementById('compressBtn');
    const smapsToggle = document.getElementById('smapsToggle');
    const filterInput = document.getElementById('filterInput');
    const detailsBox = document.getElementById('details-box');
    const loadExampleBtn = document.getElementById('loadExampleBtn');

    let currentEntries = [];
    let smapsData = {};
    let compressed = true;
    let smapsOverlay = false;
    let filterQuery = '';

    const TWO_MB = 0x200000n;
    const ONE_GB = 0x40000000n;

    const VM_FLAGS = { // https://man7.org/linux/man-pages/man5/proc_pid_smaps.5.html
        'rd': 'readable',
        'wr': 'writable',
        'ex': 'executable',
        'sh': 'shared',
        'mr': 'may read',
        'mw': 'may write',
        'me': 'may execute',
        'ms': 'may share',
        'gd': 'stack segment grows down',
        'pf': 'pure PFN range',
        'dw': 'disabled write to the mapped file',
        'lo': 'pages are locked in memory',
        'io': 'memory mapped I/O area',
        'sr': 'sequential read advise provided',
        'rr': 'random read advise provideed',
        'dc': 'do not copy area on fork',
        'de': 'do not expand area on remapping',
        'ac': 'area is accountable',
        'nr': 'swap space is not reserved for area',
        'ht': 'area uses huge tlb pages',
        'sf': 'perform synchronous page faults',
        'nl': 'non-linear mapping',
        'ar': 'architecture specific flag',
        'wf': 'wipe on fork',
        'dd': 'do not include into core dump',
        'sd': 'soft-dirty flag',
        'mm': 'mixed map area',
        'hg': 'huge page advise flag',
        'nh': 'no-huge page advise flag',
        'mg': 'mergeable advise flag',
        'um': 'userfaultfd missing pages tracking',
        'uw': 'userfaultfd wprotect pages tracking',
    };

    function parseMaps(text) {
        const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
        return lines.map(parseLine).filter(Boolean);
    }

    function parseLine(line) {
        const regex = /^([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+([-rwxps]{4})\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+):([0-9a-fA-F]+)\s+(\d+)\s*(.*)$/;
        const match = line.match(regex);
        if (!match) return null;
        const [, startStr, endStr, perms, offsetStr, major, minor, inode, pathname] = match;
        const start = BigInt('0x' + startStr);
        const end = BigInt('0x' + endStr);
        return {
            raw: line,
            start, end,
            size: end - start,
            perms,
            offset: offsetStr,
            dev: `${major}:${minor}`,
            inode: parseInt(inode, 10) || 0,
            pathname: (pathname || '').trim() || '[anonymous]',
            readable: perms[0] === 'r',
            writable: perms[1] === 'w',
            executable: perms[2] === 'x',
            shared: perms[3] === 's',
            private: perms[3] === 'p',
        };
    }

    function parseSmaps(text) {
        const data = {};
        const lines = text.split('\n');
        let currentAddr = null;
        let currentInfo = {};

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) {
                // Empty line signifies end of current block
                if (currentAddr && Object.keys(currentInfo).length > 0) {
                    data[currentAddr] = currentInfo;
                }
                currentAddr = null;
                currentInfo = {};
                continue;
            }

            // Check if this is a header line (starts with hex address range)
            const headerMatch = line.match(/^([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+/);
            if (headerMatch) {
                // Save previous block if exists
                if (currentAddr && Object.keys(currentInfo).length > 0) {
                    data[currentAddr] = currentInfo;
                }
                currentAddr = '0x' + headerMatch[1];
                currentInfo = {};
                continue;
            }

            // Parse VmFlags line
            if (line.startsWith('VmFlags:')) {
                if (currentAddr) {
                    currentInfo.vmFlags = line.replace('VmFlags:', '').trim().split(/\s+/);
                }
                continue;
            }

            // Parse key-value lines (e.g., "Size:                784 kB")
            const kvMatch = line.match(/^([A-Za-z_]+):\s+(\d+)\s*kB/i);
            if (kvMatch && currentAddr) {
                currentInfo[kvMatch[1]] = parseInt(kvMatch[2], 10) * 1024;
            }
        }

        // Save last block
        if (currentAddr && Object.keys(currentInfo).length > 0) {
            data[currentAddr] = currentInfo;
        }

        return data;
    }


    function getColor(entry) {
        const p = entry.pathname;
        if (p.includes('[stack]') || p.includes('[vdso]') || p.includes('[vvar]') || p.includes('[vsyscall]')) return '#b45309';
        if (entry.executable) return '#ea580c';
        if (entry.shared) return '#9333ea';
        if (entry.writable && (p === '[anonymous]' || p.startsWith('[anon'))) return '#2563eb';
        if (!entry.writable && entry.readable && !entry.executable) return '#16a34a';
        return '#4b5563';
    }

    function formatBytes(bytes) {
        if (bytes < 1024) return bytes + ' B';
        const units = ['KB', 'MB', 'GB'];
        let val = bytes, i = -1;
        do { val /= 1024; i++; } while (val >= 1024 && i < units.length - 1);
        return val.toFixed(2) + ' ' + units[i];
    }

    function escapeHtml(s) {
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function filterEntries(entries, q) {
        if (!q.trim()) return entries;
        const lq = q.toLowerCase();
        return entries.filter(e =>
            e.pathname.toLowerCase().includes(lq) ||
            e.perms.toLowerCase().includes(lq) ||
            e.raw.toLowerCase().includes(lq)
        );
    }

    function groupByDSO(entries) {
        const groups = [];
        let current = null;
        for (const e of entries) {
            const key = e.pathname;
            if (current && current.key === key) {
                current.entries.push(e);
            } else {
                if (current) groups.push(current);
                current = { key, entries: [e] };
            }
        }
        if (current) groups.push(current);
        return groups;
    }

    function getSmapsInfo(entry) {
        const addrKey = '0x' + entry.start.toString(16);
        return smapsData[addrKey] || null;
    }

    function render(entries) {
        canvas.innerHTML = '';
        if (!entries.length) {
            canvas.innerHTML = '<div style="padding:40px;color:#888;">No mappings to display</div>';
            return;
        }

        const filtered = filterEntries(entries, filterQuery);
        if (filtered.length === 0) {
            canvas.innerHTML = '<div style="padding:40px;color:#888;">No mappings match filter</div>';
            return;
        }

        const sorted = [...filtered].sort((a, b) => Number(a.start - b.start));
        const groups = groupByDSO(sorted);
        const minAddr = sorted[0].start;
        const maxAddr = sorted[sorted.length - 1].end;
        const totalRange = maxAddr - minAddr;
        const viewHeight = Math.max(680, 680);

        const topMargin = 40;
        const usableHeight = viewHeight - topMargin - 30;

        const colStartX = 150;
        const colSpacing = 200;
        const colWidth = 90;

        if (totalRange > 0n) {
            drawBoundaries(minAddr, maxAddr, usableHeight, topMargin);
        }

        groups.forEach((group, gi) => {
            const xCenter = colStartX + gi * colSpacing;
            const isDSO = group.key.startsWith('/') || group.key.includes('.so');

            const vline = document.createElement('div');
            vline.className = 'vcolumn';
            vline.style.left = xCenter + 'px';
            vline.style.top = topMargin + 'px';
            vline.style.height = usableHeight + 'px';
            canvas.appendChild(vline);

            const topLabel = document.createElement('div');
            topLabel.className = 'addr-top-label';
            topLabel.style.left = xCenter + 'px';
            topLabel.style.top = (topMargin - 22) + 'px';
            topLabel.textContent = '0x' + group.entries[0].start.toString(16).slice(0, 10);
            canvas.appendChild(topLabel);

            if (isDSO && group.entries.length > 1) {
                const dsoLabel = document.createElement('div');
                dsoLabel.className = 'group-dso-label';
                dsoLabel.style.left = (xCenter - 50) + 'px';
                dsoLabel.style.top = (topMargin - 8) + 'px';
                dsoLabel.textContent = 'DSO: ' + group.key.split('/').pop();
                canvas.appendChild(dsoLabel);
            }

            group.entries.forEach((entry) => {
                const ratioTop = totalRange > 0n ? Number(entry.start - minAddr) / Number(totalRange) : 0;
                let yPos = topMargin + ratioTop * usableHeight;
                let segHeight = Math.max(24, (Number(entry.size) / Number(totalRange)) * usableHeight);

                if (compressed) {
                    const idx = group.entries.indexOf(entry);
                    const total = group.entries.length;
                    const groupHeight = usableHeight * 0.65;
                    const gap = 8;
                    const each = (groupHeight - (total - 1) * gap) / total;
                    yPos = topMargin + 40 + idx * (each + gap);
                    segHeight = Math.max(26, each);
                }

                const color = getColor(entry);
                const block = document.createElement('div');
                block.className = 'segment-block';
                block.style.left = (xCenter - colWidth / 2) + 'px';
                block.style.top = yPos + 'px';
                block.style.height = segHeight + 'px';
                block.style.width = colWidth + 'px';
                block.style.borderColor = color;
                block.style.backgroundColor = `${color}18`;
                block.textContent = entry.executable ? 'RX' : (entry.writable ? 'RW' : 'RO');

                if (smapsOverlay) {
                    const smapsInfo = getSmapsInfo(entry);
                    if (smapsInfo && smapsInfo.Rss) {
                        const rssRatio = Math.min(1, smapsInfo.Rss / Number(entry.size));
                        const rssBar = document.createElement('div');
                        rssBar.className = 'rss-overlay-bar';
                        rssBar.style.left = (xCenter - colWidth / 2 + 4) + 'px';
                        rssBar.style.top = (yPos + segHeight - segHeight * rssRatio) + 'px';
                        rssBar.style.width = (colWidth - 8) + 'px';
                        rssBar.style.height = Math.max(2, segHeight * rssRatio) + 'px';
                        canvas.appendChild(rssBar);
                    }
                }

                block.addEventListener('mouseenter', (e) => {
                    showTooltip(e, entry);
                    updateDetails(entry);
                });
                block.addEventListener('mouseleave', hideTooltip);
                canvas.appendChild(block);
            });
        });

        canvas.style.minHeight = viewHeight + 'px';
        canvas.style.width = (colStartX + groups.length * colSpacing + 120) + 'px';
    }

    function drawBoundaries(min, max, usableHeight, topMargin) {
        const total = max - min;
        if (total <= 0n) return;
        const start2MB = (min / TWO_MB) * TWO_MB;
        let count = 0;
        for (let addr = start2MB; addr < max; addr += TWO_MB) {
            if (count++ > 350) break;
            const ratio = Number(addr - min) / Number(total);
            if (ratio < 0 || ratio > 1) continue;
            const y = topMargin + ratio * usableHeight;
            const line = document.createElement('div');
            line.className = 'boundary-hline';
            line.style.top = y + 'px';
            const is1GB = addr % ONE_GB === 0n;
            if (is1GB) line.style.borderTop = '2px solid #f87171';
            canvas.appendChild(line);

            const tag = document.createElement('div');
            tag.className = 'boundary-text-right';
            tag.style.top = (y - 10) + 'px';
            tag.textContent = is1GB ? '1GB' : '2MB';
            canvas.appendChild(tag);
        }
    }

    let tooltipEl = null;
    function showTooltip(e, entry) {
        if (!tooltipEl) {
            tooltipEl = document.createElement('div');
            tooltipEl.className = 'tooltip-popup';
            document.body.appendChild(tooltipEl);
        }

        const smapsInfo = getSmapsInfo(entry);
        let smapsHtml = '';
        if (smapsInfo) {
            smapsHtml = `<div style="margin-top:8px;padding-top:6px;border-top:1px solid #334155;">
          <div style="color:#10b981;font-weight:600;">Smaps</div>
          <div>RSS: ${formatBytes(smapsInfo.Rss || 0)}</div>
          <div>PSS: ${formatBytes(smapsInfo.Pss || 0)}</div>`;
            if (smapsInfo.vmFlags) {
                smapsHtml += `<div style="margin-top:6px;color:#f59e0b;font-weight:600;">VM Flags</div>
            <div style="display:flex;flex-wrap:wrap;gap:2px;">${smapsInfo.vmFlags.map(f => `<span class="vmflag-chip">${f}</span>`).join('')}</div>
            <div style="margin-top:4px;font-size:10px;color:#a5b4fc;">${smapsInfo.vmFlags.map(f => `${f}: ${VM_FLAGS[f] || f}`).join('; ')}</div>`;
            }
            smapsHtml += `</div>`;
        }

        tooltipEl.innerHTML = `
        <strong>${escapeHtml(entry.pathname)}</strong><br>
        ${entry.perms} . ${formatBytes(Number(entry.size))}<br>
        <span style="font-family:monospace;">0x${entry.start.toString(16)} - 0x${entry.end.toString(16)}</span>
        ${smapsHtml}`;
        tooltipEl.style.left = Math.min(e.clientX + 16, window.innerWidth - 360) + 'px';
        tooltipEl.style.top = (e.clientY - 20) + 'px';
        tooltipEl.style.display = 'block';
    }

    function hideTooltip() {
        if (tooltipEl) tooltipEl.style.display = 'none';
    }

    function updateDetails(entry) {
        const smapsInfo = getSmapsInfo(entry);
        let smapsDetail = '';
        if (smapsInfo) {
            smapsDetail = `[SMAPS]\nRSS: ${formatBytes(smapsInfo.Rss || 0)}\nPSS: ${formatBytes(smapsInfo.Pss || 0)}`;
            if (smapsInfo.vmFlags) {
                smapsDetail += `\n[VM FLAGS] \n` + smapsInfo.vmFlags.map(f => `- ${VM_FLAGS[f] || f}`).join('\n');
            }
        }
        detailsBox.textContent = `[MAPS]
Path: ${entry.pathname}
Permissions: ${entry.perms}
Start: 0x${entry.start.toString(16)}
End: 0x${entry.end.toString(16)}
Size: ${formatBytes(Number(entry.size))}
2MB aligned: ${entry.start % TWO_MB === 0n ? 'yes' : 'no'}
1GB aligned: ${entry.start % ONE_GB === 0n ? 'yes' : 'no'}
${smapsDetail}`;
    }

    function refresh() {
        currentEntries = parseMaps(mapsInput.value);
        smapsData = parseSmaps(smapsInput.value);
        render(currentEntries);
    }

    renderBtn.addEventListener('click', refresh);
    compressBtn.addEventListener('click', () => {
        compressed = !compressed;
        compressBtn.classList.toggle('active', compressed);
        render(currentEntries);
    });
    smapsToggle.addEventListener('click', () => {
        smapsOverlay = !smapsOverlay;
        smapsToggle.classList.toggle('active', smapsOverlay);
        render(currentEntries);
    });
    filterInput.addEventListener('input', (e) => {
        filterQuery = e.target.value;
        render(currentEntries);
    });
    loadExampleBtn.addEventListener('click', () => {
        mapsInput.value = exampleMaps;
        smapsInput.value = exampleSmaps;
        refresh();
    });

    window.addEventListener('resize', () => {
        if (currentEntries.length) render(currentEntries);
    });

    refresh();
})();
