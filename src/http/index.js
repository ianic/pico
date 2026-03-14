const isVisible = (element) => {
    return element.style.display != 'none';
}

const navigatePage = (page) => {
    showPage(page);
    history.pushState({ page: page }, page, "");
}

const showPage = (page) => {
    page = page || "home";

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


const drawGraph = (intervals, svgElementId = "chart", interactive = true) => {
    const element = document.getElementById(svgElementId);
    element.innerHTML = "";
    
    // Transform to stepped line data points
    const data = intervals.flatMap(d => [{x: d.from, y: d.temp}]);
    const last = intervals[intervals.length-1];
    data.push({x: last.to, y: last.temp});

    const margin = {top: 20, right: 5, bottom: 40, left: 20};
    const width = element.clientWidth - margin.left - margin.right;
    const height = 200 - margin.top - margin.bottom;

    const svg = d3.select("#" + svgElementId)
          .append("g")
          .attr("transform", `translate(${margin.left},${margin.top})`);

    const x = d3.scaleLinear()
          .domain([0, 144])
          .range([0, width]);

    const y = d3.scaleLinear()
          .domain([d3.min(data, d => d.y), d3.max(data, d => d.y)])
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
        .attr("stroke", "steelblue")
        .attr("stroke-width", 2)
        .attr("d", line);

    // Draw points
    svg.selectAll("circle")
        .data(data)
        .enter().append("circle")
        .attr("cx", d => x(d.x))
        .attr("cy", d => y(d.y))
        .attr("r", 3)
        .attr("fill", "steelblue")
        .attr("stroke", "white")
        .attr("stroke-width", 2);             

    const xAxis = d3.axisBottom(x)
          .tickValues(data.flatMap(d => d.x))
          .tickFormat( (d, i) => formatLabel(d) );
    
    const yAxis = d3.axisLeft(y)
          .tickValues([... new Set(data.flatMap(d => d.y))])
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

    if (interactive) {
        // Rectangle for getting clicks
        svg.append("rect")
            .attr("width", width)
            .attr("height", height)
            .style("fill", "none")
            .style("pointer-events", "all")
            .on("click", function(event) {
                // Get mouse coordinates relative to the chart
                const [mx, my] = d3.pointer(event);
                // Invert X coordinate to data value
                const xValue = parseInt(x.invert(mx));
                const yValue = parseInt(y.invert(my));
                graphSelect(xValue, yValue);
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

const showHome = () => {
    const profile = getCurrentProfile();
    document.getElementById('home-profile-name').textContent = profile.name;
    drawGraph(profile.intervals, 'home-chart', false);
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

const scheduleIsDirty = () => JSON.stringify(schedule) !== scheduleSnapshot;

const setUpdateDirty = () => {
    document.getElementById('set-update').disabled = !scheduleIsDirty();
};

const scheduleBack = () => {
    Object.assign(schedule, JSON.parse(scheduleSnapshot));
    navigatePage('home');
};

const scheduleUpdate = () => {
    navigatePage('home');
};

const setModeChange = (mode) => {
    schedule.mode = mode;
    ['fixed', 'workday-weekend', 'daily'].forEach(m => {
        document.getElementById('set-' + m).style.display = m === mode ? 'block' : 'none';
    });
    setUpdateDirty();
};

const showSet = () => {
    scheduleSnapshot = JSON.stringify(schedule);
    const days = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'];
    ['set-fixed-profile', 'set-workday-profile', 'set-weekend-profile',
     ...days.map(d => `set-daily-${d}`)].forEach(id => {
        const sel = document.getElementById(id);
        sel.innerHTML = '';
        profiles.forEach((p, i) => sel.add(new Option(p.name, i)));
    });
    document.querySelector(`input[name="schedule-mode"][value="${schedule.mode}"]`).checked = true;
    setModeChange(schedule.mode);
    document.getElementById('set-fixed-profile').value = schedule.fixed;
    document.getElementById('set-workday-profile').value = schedule.workday;
    document.getElementById('set-weekend-profile').value = schedule.weekend;
    days.forEach((d, i) => document.getElementById(`set-daily-${d}`).value = schedule.daily[i]);
    document.getElementById('set-update').disabled = true;
};

const showProfiles = () => {
    const container = document.getElementById('profiles-container');
    container.innerHTML = '';
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
    document.getElementById('edit-update').disabled = !editIsDirty();
}

const editBack = () => {
    navigatePage('profiles');
}

const editUpdate = () => {
    currentProfile.name = document.getElementById('profile-name').value;
    profiles[currentProfileIndex] = JSON.parse(JSON.stringify(currentProfile));
    navigatePage('profiles');
}

const edit = (profile, index) => {
    currentProfileIndex = index;
    currentProfile = JSON.parse(JSON.stringify(profile));
    editSnapshot = JSON.stringify({name: profile.name, intervals: profile.intervals});
    navigatePage('edit');
    showProfile();
    selectRow(currentProfile.intervals.length > 1 ? 1 : 0);
}

//edit(profiles[3], 3);
