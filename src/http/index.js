const isVisible = (element) => {
    return element.style.display != 'none';
}

let currentPage = 'home';

const navigatePage = (page) => {
    showPage(page);
    history.pushState({ page: page }, page, "");
}

const showPage = (page) => {
    page = page || "home";
    currentPage = page;

    // show/hide container
    const container = (page) => {
        const $home = document.getElementById('home-container');
        const $edit = document.getElementById('edit-container');
        const $profiles = document.getElementById('profiles-container');
        const $set = document.getElementById('set-container');
        const $current = document.getElementById(page + '-container'); 
        if (!$current) return;

        $home.style.display = 'none';
        $edit.style.display = 'none';
        $set.style.display = 'none';
        $profiles.style.display = 'none';
        $current.style.display = 'block';
    }
    container(page);

    if (page === 'home') showHome();
    if (page === 'profiles') showProfiles();
    if (page === 'set') showSet();

    // breadcrumb
    const crumbHome = `<li class="breadcrumb-item"><a href="#" onclick="navigatePage('home'); return false;">Home</a></li>`;
    const crumbs = {
        home:     `<li class="breadcrumb-item active">Home</li>`,
        set:      crumbHome + `<li class="breadcrumb-item active">Schedule</li>`,
        profiles: crumbHome + `<li class="breadcrumb-item active">Profiles</li>`,
        edit:     crumbHome +
                  `<li class="breadcrumb-item"><a href="#" onclick="navigatePage('profiles'); return false;">Profiles</a></li>` +
                  `<li class="breadcrumb-item active">Edit Profile</li>`,
    };
    document.getElementById('breadcrumb').innerHTML = crumbs[page] ?? crumbs.home;

    // set page title
    const title = (page) => {
        switch (page) {
        case "set": return "Pico - Schedule";
        case "profiles": return "Pico - Profiles";
        case "edit": return "Pico - Edit Profile";
        default: return "Pico";
        }
    }
    document.title = title(page);

    // set active link
    const link = (page) => {
        if (page == 'edit') {
            return;  
        } 
        const $home = document.getElementById('home-link');
        //const $edit = document.getElementById('edit-link');
        const $set = document.getElementById('set-link');
        const $profiles = document.getElementById('profiles-link');
        let $current = document.getElementById(page + '-link'); 
        
        $home.classList.remove("active");
        //$edit.classList.remove("active");
        $set.classList.remove("active");
        $profiles.classList.remove("active");
        $current.classList.add("active");
    }
    link(page);

    // collapse navigation bar links
    const navbarCollapse = document.getElementById('navbarNavAltMarkup');
    const bsCollapse = new bootstrap.Collapse(navbarCollapse, {
        toggle: false // Do not toggle if already closed
    });
    bsCollapse.hide();
};



// Handle the Back Button
window.onpopstate = (event) => {
    showPage(event.state?.page || "home");
};


// Find target temperature at interval x using step-after logic
const tooltipTargetTemp = (intervals, xVal) => {
    for (let i = intervals.length - 1; i >= 0; i--) {
        if (intervals[i].from <= xVal) return intervals[i].temp;
    }
    return null;
};

// Find actual temperature at interval x (readings are sorted, forward-filled)
const tooltipActualTemp = (readings, xVal) => {
    let temp = null;
    for (const r of readings) {
        if (r.x > xVal) break;
        temp = r.y;
    }
    return temp;
};

const drawGraph = (intervals, svgElementId = "chart", interactive = true, readings = null, heatingData = null) => {
    const element = document.getElementById(svgElementId);
    element.innerHTML = "";

    // Transform to stepped line data points
    const data = intervals.flatMap(d => [{x: d.from, y: d.temp}]);
    const last = intervals[intervals.length-1];
    data.push({x: last.to, y: last.temp});

    const heatingHeight = 45;
    const heatingGap    = 8;
    const svgHeight = heatingData ? 200 + heatingHeight + heatingGap : 200;
    element.setAttribute('height', svgHeight);

    const margin = {top: 20, right: 5, bottom: 40, left: 20};
    const width  = element.clientWidth - margin.left - margin.right;
    const height = 200 - margin.top - margin.bottom; // temperature area, always 140px

    const svg = d3.select("#" + svgElementId)
          .append("g")
          .attr("transform", `translate(${margin.left},${margin.top})`);

    const x = d3.scaleLinear()
          .domain([0, 144])
          .range([0, width]);

    const yMin = readings ? Math.min(d3.min(data, d => d.y), d3.min(readings, d => d.y)) : d3.min(data, d => d.y);
    const yMax = readings ? Math.max(d3.max(data, d => d.y), d3.max(readings, d => d.y)) : d3.max(data, d => d.y);
    const y = d3.scaleLinear()
          .domain([yMin, yMax])
          .range([height, 0]);

    // Stepped line generator (step-after)
    const line = d3.line()
          .x(d => x(d.x))
          .y(d => y(d.y))
          .curve(d3.curveStepAfter);  // horizontal then vertical

    // Draw line
    svg.append("path")
        .datum(data)
        .attr("fill", "none")
        .attr("stroke", "#2196F3")
        .attr("stroke-width", 2)
        .attr("d", line);

    // Draw target points
    svg.selectAll("circle")
        .data(data)
        .enter().append("circle")
        .attr("cx", d => x(d.x))
        .attr("cy", d => y(d.y))
        .attr("r", 3)
        .attr("fill", "#2196F3")
        .attr("stroke", "white")
        .attr("stroke-width", 2);

    // Draw actual readings
    if (readings) {
        const readingsLine = d3.line()
              .x(d => x(d.x))
              .y(d => y(d.y))
              .curve(d3.curveLinear);

        svg.append("path")
            .datum(readings)
            .attr("fill", "none")
            .attr("stroke", "#4CAF50")
            .attr("stroke-width", 1.5)
            .attr("d", readingsLine);
    }

    const xChanges = data.map(d => d.x);
    const xHours = d3.range(0, 145, 36);
    const xTicks = [...new Set([...xHours, ...xChanges])].sort((a, b) => a - b);
    const xAxis = d3.axisBottom(x)
          .tickValues(xTicks)
          .tickFormat(d => formatLabel(d));

    const yTicks = d3.range(Math.floor(yMin), Math.ceil(yMax) + 1);
    const yAxis = d3.axisLeft(y)
          .tickValues(yTicks)
          .tickFormat(d3.format("d"));
    
    // Axes
    svg.append("g")    
        .attr("transform", `translate(0,${height})`)
        .call(xAxis)
    // grid lines
        .call(g => g.select(".domain").remove())
        .call(g => g.selectAll(".tick line").clone()
              .attr("y2", -height)
              .attr("stroke-opacity", 0.1))
    // labels
        .selectAll("text")
        .attr("dx", "-2em")
        .attr("transform", "rotate(-45)");


    svg.append("g")
        .call(yAxis)
    // grid lines
        .call(g => g.select(".domain").remove())
        .call(g => g.selectAll(".tick line").clone()
              .attr("x2", width)
              .attr("stroke-opacity", 0.1));

    if (heatingData) {
        const hTop    = height + margin.bottom + heatingGap;
        const barW    = Math.max(1, width / 144);
        const hScale  = d3.scaleLinear().domain([0, 100]).range([0, heatingHeight]);

        // separator
        svg.append("line")
            .attr("x1", 0).attr("x2", width)
            .attr("y1", hTop - heatingGap / 2).attr("y2", hTop - heatingGap / 2)
            .attr("stroke", "#ddd").attr("stroke-width", 1);

        const hLineY = hTop - heatingGap / 2;

        // bars
        svg.selectAll(".h-bar")
            .data(heatingData)
            .enter().append("rect")
            .attr("class", "h-bar")
            .attr("x", d => x(d.x))
            .attr("y", hLineY)
            .attr("width", barW)
            .attr("height", d => hScale(d.pct))
            .attr("fill", "#FF6D00")
            .attr("opacity", 0.75);

        // "heat" label at left
        svg.append("text")
            .attr("x", 0).attr("y", hLineY + 10)
            .attr("font-size", 9).attr("fill", "#aaa")
            .text("heat %");
    }

    const overlay = svg.append("rect")
        .attr("width", width)
        .attr("height", height)
        .style("fill", "none")
        .style("pointer-events", "all")
        .on("mousemove", function(event) {
            const [mx] = d3.pointer(event);
            const xVal = Math.round(x.invert(mx));
            if (xVal < 0 || xVal > 144) return;

            const targetTemp = tooltipTargetTemp(intervals, xVal);
            const actualTemp = readings ? tooltipActualTemp(readings, xVal) : null;
            const heating    = heatingData ? (heatingData.find(d => d.x === xVal) ?? null) : null;

            let html = `<strong>${formatLabel(xVal)}</strong>`;
            if (targetTemp !== null) html += `<br>Target: ${targetTemp}°C`;
            if (actualTemp !== null) html += `<br>Actual: ${actualTemp}°C`;
            if (heating !== null)    html += `<br>Heat: ${heating.pct}%`;

            const tip = document.getElementById('graph-tooltip');
            tip.innerHTML = html;
            tip.style.display = 'block';
            tip.style.left = (event.pageX + 14) + 'px';
            tip.style.top  = (event.pageY - 38) + 'px';
        })
        .on("mouseleave", function() {
            document.getElementById('graph-tooltip').style.display = 'none';
        });

    if (interactive) {
        overlay.on("click", function(event) {
            const [mx, my] = d3.pointer(event);
            graphSelect(parseInt(x.invert(mx)), parseInt(y.invert(my)));
        });
    }

}

function formatTemplate(template, values) {
    return template.replace(/\$\{(\w+)\}/g, (match, key) => values[key] ?? match);
}

const formatLabel = (value) => {
    const hour = Math.floor(value / 6);
    const min = (value - hour * 6) * 10;
    const label = `${hour.toString().padStart(2, '0')}:${min.toString().padStart(2, '0')}`;
    return label;
}

const graphSelect = (x, y) => {
    const profile = currentProfile;
    for (var i = 0; i < profile.intervals.length; i++) {
        const interval = profile.intervals[i];
        if (interval.from <= x && interval.to >= x) {
            selectRow(i);
            break;
        }
    }
}

const selectRow = (idx) => {
    const interval = currentProfile.intervals[idx];

    const $from = document.getElementById('select-from');
    const $to = document.getElementById('select-to');
    const $temp = document.getElementById('select-temp');

    $from.value = interval.from;
    $to.value = interval.to;
    $temp.value = interval.temp;
}

function showProfile() {
    const profile = currentProfile;
    const $name = document.getElementById('profile-name');
    $name.value = profile.name;
    
    // clear table
    const table = document.getElementById('intervals-table');
    while (table.rows.length > 2) {
        table.deleteRow(-1);  // -1 = last row
    }
    
    const tbody = document.querySelector('#intervals-table tbody');
    const rowTemplate = document.getElementById('row-template');
    for (let i=0; i<profile.intervals.length; i+=1) {             
        const row = profile.intervals[i];
        const html = formatTemplate(rowTemplate.innerHTML, {
            from: formatLabel(row.from),
            to: formatLabel(row.to),
            temp: row.temp,
            idx: i,                               
        });
        tbody.insertAdjacentHTML('beforeend', html);    
    }
    
    drawGraph(profile.intervals);
    editUpdateDirty();
}

let profiles = [
    {
        "name": "work from office",
        "intervals": [
            {
                "from": 0,
                "to": 39,
                "temp": 15
            },
            {
                "from": 39,
                "to": 45,
                "temp": 21
            },
            {
                "from": 45,
                "to": 99,
                "temp": 18
            },
            {
                "from": 99,
                "to": 120,
                "temp": 20
            },
            {
                "from": 120,
                "to": 135,
                "temp": 22
            },
            {
                "from": 135,
                "to": 144,
                "temp": 15
            }
        ]
    },
    {
        name: "work from home",
        intervals: [
            {from: 0, to: 45, temp: 15},  
            {from: 45, to: 99, temp: 21},
            {
                "from": 99,
                "to": 120,
                "temp": 20
            },
            {
                "from": 120,
                "to": 135,
                "temp": 22
            },
            {
                "from": 135,
                "to": 144,
                "temp": 15
            }            
        ],
    },
    {
        "name": "weekend",
        "intervals": [
            {
                "from": 0,
                "to": 45,
                "temp": 15
            },
            {
                "from": 45,
                "to": 120,
                "temp": 21
            },
            {
                "from": 120,
                "to": 132,
                "temp": 22
            },
            {
                "from": 132,
                "to": 138,
                "temp": 20
            },
            {
                "from": 138,
                "to": 144,
                "temp": 19
            }
        ]
    },
    {
        name: "away",
        intervals: [
            {from: 0, to: 144, temp: 10}
        ]
    }
];

const selectChange = (button) => {
    const $from = document.getElementById('select-from');
    const $to = document.getElementById('select-to');
    const $add = document.getElementById('add');

    const fromValue = parseInt($from.value);
    const toValue = parseInt($to.value);

    if (toValue <= (fromValue + 3)) {
        if (button == $from) {
            $to.value = fromValue + 3;
        } else {
            $from.value = toValue - 3;
        }
    }

    $add.disabled = !(parseInt($from.value) < parseInt($to.value));
}

const intervalAdd = (button) => {
    const $from = document.getElementById('select-from');
    const $to = document.getElementById('select-to');
    const $temp = document.getElementById('select-temp');
    
    const newRow = {
        from: parseInt($from.value),
        to: parseInt($to.value),
        temp: parseFloat($temp.value),
    };

    if (newRow.from >= newRow.to) {
        return;
    }
    let intervals = currentProfile.intervals;

    for (let i=0; i < intervals.length; i+=1) {             
        let row = intervals[i];
        if (row.from >= newRow.from && row.from < newRow.to) {
            row.from = newRow.to;
        }
        if (row.to >= newRow.from && row.to <= newRow.to) {
            row.to = newRow.from;
        }
    }
    intervals = intervals.filter((row) => !(row.from >= newRow.from && row.to <= newRow.to));
    intervals = intervals.filter((row) => (row.to >= row.from));
    
    for (let i=0; i < intervals.length; i+=1) {             
        let row = intervals[i];
        if (row.from <= newRow.from && row.to >= newRow.to) {
            if (row.to > newRow.to) {
                intervals.push({
                    from: newRow.to,
                    to: row.to,
                    temp: row.temp,
                });
            }
            row.to = newRow.from;
        }
    };
    
    intervals.push(newRow);
    currentProfile.intervals = intervals.sort((a, b) => a.from - b.from);

    showProfile();
}

document.addEventListener('DOMContentLoaded', async () => {
    const selectFrom = document.getElementById('select-from');
    const selectTo = document.getElementById('select-to');
    const selectTemp = document.getElementById('select-temp');

    for (i = 0; i<=144; i+=1) {
        const hour = Math.floor(i / 6);
        const min = (i - hour * 6) * 10;
        const label = `${hour.toString().padStart(2, '0')}:${min.toString().padStart(2, '0')}`;

        if (i > 2) {
            selectTo.add(new Option(label, i));
        }
        if (i < 142) {
            selectFrom.add(new Option(label, i));
        }
    }
    for (i = 10; i<=30; i+=1) {
        selectTemp.add(new Option(i, i)); 
    }
    selectFrom.value = 39;
    selectTo.value = 144;
    selectTemp.value = 21;
    
    getLast();
    showHome();
});

let resizeTimer;
window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
        switch (currentPage) {
            case 'home':     drawHomeGraph(); break;
            case 'profiles': showProfiles(); break;
            case 'edit':     showProfile();  break;
        }
    }, 150);
});

const onButton = (button) => {
    button.disabled = true;
    fetch('http://pico.lan/toggle');
    //.then(response => response.arrayBuffer())
    //.then(buffer => updateCurrent(buffer));
}

const parseReading = (dv, idx) => {
    const unix = dv.getUint32(idx, true);  
    const temp = dv.getUint16(idx + 4, true);
    const flags = dv.getUint8(idx + 6, true);
    const date = new Date(unix * 1000);
    return {
        unix: unix,
        date: date,
        time: date.toTimeString().slice(0,8),                 
        temp: temp / 16,
        relay: flags > 0,
    };
}

const getLast = () => {
    fetch('http://pico.lan/last')
        .then(response => response.arrayBuffer())
        .then(buffer => {
            updateCurrent(buffer);
            setTimeout(getLast, 5000);
        })
        .catch(error => {
            console.error('Fetch failed:', error);
            setTimeout(getLast, 5000);
        });
}

const updateCurrent = (buffer) => {
    const dv = new DataView(buffer);
    const reading = parseReading(dv, 0);
    
    const value = document.getElementById('value');
    const button = document.getElementById('button');
    const desc = document.getElementById('desc');
    
    const time = reading.date.toTimeString().slice(0,8);            
    const text = reading.temp.toFixed(1) + "°C"
    
    desc.textContent = `${time} ${reading.temp}`;
    value.textContent = text;
    if (reading.relay) {
        value.classList.add('active');
        button.textContent = "GASI";
    } else {
        value.classList.remove('active');
        button.textContent = "PALI";                 
    }
    button.disabled = false;
}

const getAll = () => {
    fetch('http://pico.lan/all')
        .then(response => response.arrayBuffer())
        .then(buffer => {                     
            const dv = new DataView(buffer);  
            let readings = [];
            for (idx = 0; idx + 7 <= dv.byteLength; idx += 7) {
                readings.push(parseReading(dv, idx));
            }
            console.log(readings);                     
        });
}

const getCurrentProfile = () => {
    const day = new Date().getDay(); // 0=Sun, 1=Mon, ..., 6=Sat
    switch (schedule.mode) {
        case 'fixed':
            return profiles[schedule.fixed];
        case 'workday-weekend':
            return (day >= 1 && day <= 5) ? profiles[schedule.workday] : profiles[schedule.weekend];
        case 'daily': {
            const idx = day === 0 ? 6 : day - 1; // map to 0=Mon..6=Sun
            return profiles[schedule.daily[idx]];
        }
    }
}

// Convert raw readings (sparse, timestamped) to one-per-10min-interval array for today.
// Each interval value is the last reading at or before the end of that interval.
const readingsToIntervals = (readings) => {
    if (readings.length === 0) return [];

    const sorted = [...readings].sort((a, b) => a.unix - b.unix);

    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const midnight = today.getTime() / 1000;

    const points = sorted
        .map(r => ({ x: Math.floor((r.unix - midnight) / 600), y: r.temp }))
        .filter(p => p.x >= 0 && p.x < 144);

    if (points.length === 0) return [];

    const maxX = points[points.length - 1].x;
    const result = [];
    let currentTemp = points[0].y;
    let pi = 0;

    for (let x = points[0].x; x <= maxX; x++) {
        while (pi < points.length && points[pi].x === x) {
            currentTemp = points[pi].y;
            pi++;
        }
        result.push({ x, y: currentTemp });
    }

    return result;
};

// Compute heating % per 10-min interval from time-weighted relay state changes.
const readingsToHeating = (readings) => {
    if (readings.length === 0) return [];

    const sorted = [...readings].sort((a, b) => a.unix - b.unix);

    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const midnight = today.getTime() / 1000;
    const intervalSec = 600;

    const firstX = Math.max(0, Math.floor((sorted[0].unix - midnight) / intervalSec));
    const lastX  = Math.floor((sorted[sorted.length - 1].unix - midnight) / intervalSec);
    if (lastX < 0) return [];

    const result = [];
    for (let xi = firstX; xi <= lastX; xi++) {
        const iStart = midnight + xi * intervalSec;
        const iEnd   = iStart + intervalSec;

        let stateAtStart = false;
        const changes = [];
        for (const r of sorted) {
            if (r.unix < iStart)  stateAtStart = r.relay;
            else if (r.unix < iEnd) changes.push(r);
        }

        let onTime = 0;
        let cur = stateAtStart;
        let t   = iStart;
        for (const r of changes) {
            if (cur) onTime += r.unix - t;
            t = r.unix;
            cur = r.relay;
        }
        if (cur) onTime += iEnd - t;

        result.push({ x: xi, pct: Math.round(onTime / intervalSec * 100) });
    }
    return result;
};

const showHome = async () => {
    // Fallback fake temp readings
    let tempIntervals = Array.from({length: 90}, (_, i) => ({
        x: 18 + i,
        y: parseFloat((17 + 3.5 * Math.sin((i - 20) / 22) + Math.sin(i / 4.5) * 0.6).toFixed(1)),
    }));

    try {
        const response = await fetch('http://pico.lan/all');
        const buffer = await response.arrayBuffer();
        const dv = new DataView(buffer);
        const readings = [];
        for (let idx = 0; idx + 7 <= dv.byteLength; idx += 7) {
            readings.push(parseReading(dv, idx));
        }
        if (readings.length > 0) {
            tempIntervals = readingsToIntervals(readings);
        }
    } catch (e) {
        console.error('Failed to fetch readings:', e);
    }

    // Fake heating % (relay always false currently, replace with readingsToHeating later)
    homeCache.heating = tempIntervals.map(r => ({
        x:   r.x,
        pct: Math.max(0, Math.min(100, Math.round(55 + 40 * Math.sin((r.x - 25) / 18)))),
    }));
    homeCache.readings = tempIntervals;

    drawHomeGraph();
}

const homeCache = { readings: null, heating: null };

const drawHomeGraph = () => {
    const profile = getCurrentProfile();
    document.getElementById('home-profile-name').textContent = profile.name;
    drawGraph(profile.intervals, 'home-chart', false, homeCache.readings, homeCache.heating);
}

let schedule = {
    "mode": "workday-weekend",
    "fixed": 3,
    "workday": 0,
    "weekend": 2,
    "daily": [
        0,
        1,
        2,
        3,
        2,
        3,
        0
    ]
};

let scheduleSnapshot = null;
let scheduleDraft = null;

const scheduleIsDirty = () => JSON.stringify(scheduleDraft) !== scheduleSnapshot;

const setUpdateDirty = () => {
    document.getElementById('set-update').disabled = !scheduleIsDirty();
};

const scheduleBack = () => {
    navigatePage('home');
};

const scheduleUpdate = () => {
    Object.assign(schedule, scheduleDraft);
    navigatePage('home');
};

const setModeChange = (mode) => {
    scheduleDraft.mode = mode;
    ['fixed', 'workday-weekend', 'daily'].forEach(m => {
        document.getElementById('set-' + m).style.display = m === mode ? 'block' : 'none';
    });
    setUpdateDirty();
};

const showSet = () => {
    scheduleDraft = JSON.parse(JSON.stringify(schedule));
    scheduleSnapshot = JSON.stringify(schedule);
    const days = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'];
    ['set-fixed-profile', 'set-workday-profile', 'set-weekend-profile',
     ...days.map(d => `set-daily-${d}`)].forEach(id => {
        const sel = document.getElementById(id);
        sel.innerHTML = '';
        profiles.forEach((p, i) => sel.add(new Option(p.name, i)));
    });
    document.querySelector(`input[name="schedule-mode"][value="${scheduleDraft.mode}"]`).checked = true;
    setModeChange(scheduleDraft.mode);
    document.getElementById('set-fixed-profile').value = scheduleDraft.fixed;
    document.getElementById('set-workday-profile').value = scheduleDraft.workday;
    document.getElementById('set-weekend-profile').value = scheduleDraft.weekend;
    days.forEach((d, i) => document.getElementById(`set-daily-${d}`).value = scheduleDraft.daily[i]);
    document.getElementById('set-update').disabled = true;
};

const showProfiles = () => {
    const container = document.getElementById('profiles-container');
    container.innerHTML = '<div class="mb-4"><button type="button" class="btn btn-primary" onclick="newProfile()">New</button></div>';
    profiles.forEach((profile, i) => {
        const svgId = `profile-chart-${i}`;
        const card = document.createElement('div');
        card.className = 'mb-4';
        card.innerHTML = `<h5 class="text-capitalize">${profile.name}</h5><svg id="${svgId}" width="100%" height="200" style="cursor:pointer"></svg>`;
        container.appendChild(card);
        drawGraph(profile.intervals, svgId, false);
        card.querySelector('svg').addEventListener('click', () => edit(profile, i));
    });
}

let currentProfile = null;
let currentProfileIndex = null;
let editSnapshot = null;

const editIsDirty = () => {
    const name = document.getElementById('profile-name').value;
    return JSON.stringify({name, intervals: currentProfile.intervals}) !== editSnapshot;
}

const editUpdateDirty = () => {
    const name = document.getElementById('profile-name').value;
    const originalName = JSON.parse(editSnapshot).name;
    document.getElementById('edit-update').disabled = !editIsDirty();
    document.getElementById('edit-save-as-new').disabled =
        currentProfileIndex === -1 || name === originalName;
}

const editBack = () => {
    navigatePage('profiles');
}

const editUpdate = () => {
    currentProfile.name = document.getElementById('profile-name').value;
    const copy = JSON.parse(JSON.stringify(currentProfile));
    if (currentProfileIndex === -1) {
        profiles.push(copy);
    } else {
        profiles[currentProfileIndex] = copy;
    }
    navigatePage('profiles');
}

const saveAsNew = () => {
    const copy = JSON.parse(JSON.stringify(currentProfile));
    copy.name = document.getElementById('profile-name').value;
    profiles.push(copy);
    navigatePage('profiles');
}

// Returns a description of which schedule slot uses this profile, or null if none.
const isProfileInUse = () => {
    const idx = currentProfileIndex;
    if (schedule.fixed === idx) return 'used in Fixed schedule';
    if (schedule.workday === idx) return 'used as Workday schedule';
    if (schedule.weekend === idx) return 'used as Weekend schedule';
    const days = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'];
    for (let i = 0; i < 7; i++) {
        if (schedule.daily[i] === idx) return `used in Daily schedule (${days[i]})`;
    }
    return null;
};

const editUpdateDelete = () => {
    const isNew = currentProfileIndex === -1;
    const inUse = isNew ? null : isProfileInUse();
    document.getElementById('edit-delete').disabled = isNew || !!inUse;
    document.getElementById('edit-delete-note').textContent = inUse ? `Cannot delete, ${inUse}` : '';
};

const deleteProfile = () => {
    const idx = currentProfileIndex;
    profiles.splice(idx, 1);
    // Shift schedule indices that pointed past the deleted profile
    const adjust = i => i > idx ? i - 1 : i;
    schedule.fixed   = adjust(schedule.fixed);
    schedule.workday = adjust(schedule.workday);
    schedule.weekend = adjust(schedule.weekend);
    schedule.daily   = schedule.daily.map(adjust);
    navigatePage('profiles');
};

const newProfile = () => {
    edit({name: 'New Profile', intervals: [{from: 0, to: 144, temp: 20}]}, -1);
};

const edit = (profile, index) => {
    currentProfileIndex = index;
    currentProfile = JSON.parse(JSON.stringify(profile));
    editSnapshot = JSON.stringify({name: profile.name, intervals: profile.intervals});
    navigatePage('edit');
    showProfile();
    selectRow(0);
    editUpdateDelete();
}

//edit(profiles[3], 3);
