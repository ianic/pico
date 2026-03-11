active=$(hyprctl activewindow -j | jq -r '.address')
address=$(hyprctl clients -j | jq -r '.[]|select((.class=="chromium") and (.title == "Pico - Chromium"))|.address' | head -n1)

hyprctl dispatch focuswindow address:$address
hyprctl dispatch sendshortcut ctrl,r,address:$address
hyprctl dispatch focuswindow address:$active
