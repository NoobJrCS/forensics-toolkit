def generate_timeline(log_content):
    timeline = []
    lines = log_content.decode('utf-8').split('\n')
    
    for line in lines:
        if not line.strip(): 
            continue
            
        # Standard Linux logs start with: "Mar 12 10:00:01" (Month, Day, Time)
        parts = line.split(maxsplit=4)
        
        if len(parts) >= 5:
            timestamp = f"{parts[0]} {parts[1]} {parts[2]}"
            event = parts[4] # The rest of the log message
            
            # Flag suspicious events for the timeline
            is_suspicious = "Failed password" in event or "error" in event.lower()
            
            timeline.append({
                'timestamp': timestamp,
                'event': event,
                'suspicious': is_suspicious
            })
            
    return timeline