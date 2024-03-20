import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.graph_objs as go
from scapy.layers.inet import TCP, UDP
from scapy.all import rdpcap

app = dash.Dash(__name__)
server = app.server
# Load initial data
packets = rdpcap('iperf-mptcp-0-0.pcap')
packet_index = 0
max_packets_per_update = 100

initial_trace = go.Scatter(
    x=[packet.time for packet in packets[:max_packets_per_update]],
    y=[packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport for packet in packets[:max_packets_per_update] if packet.haslayer(TCP) or packet.haslayer(UDP)],
    mode='lines',
    marker=dict(color='skyblue'),
    name='Destination Port'
)

initial_layout = go.Layout(
    xaxis=dict(title='Timestamp'),
    yaxis=dict(title='Destination Port'),
    title='Destination Port vs. Timestamp',
    showlegend=True
)

app.layout = html.Div([
    html.H1("Network Traffic Analysis Dashboard", style={'textAlign': 'center'}),  # Title
    html.H2("Live Graph", style={'textAlign': 'center', 'color': 'gray'}),  # Subtitle
    dcc.Graph(id='graph', figure={'data': [initial_trace], 'layout': initial_layout}),
    dcc.Interval(
        id='interval-component',
        interval=1000,  # in milliseconds
        n_intervals=0
    ),
    html.Div(id='pie-chart-container'),
    html.Div([
        html.P("The line graph above shows the distribution of destination ports over time."),
        html.P("The pie chart below displays the distribution of packet protocols, including TCP, UDP, SSH, and FTP.")
    ])
])

@app.callback(
    [Output('graph', 'figure'),
     Output('pie-chart-container', 'children')],
    [Input('interval-component', 'n_intervals')]
)
def update_graph(n_intervals):
    global packet_index
    global packets

    # Determine the range of packets to process and plot
    start_index = packet_index
    end_index = min(packet_index + max_packets_per_update, len(packets))

    # Process packets within the range
    dest_ports = []
    timestamps = []
    for packet in packets[start_index:end_index]:
        if packet.haslayer(TCP):
            dest_ports.append(packet[TCP].dport)
        elif packet.haslayer(UDP):
            dest_ports.append(packet[UDP].dport)
        timestamps.append(packet.time)

    # Update the trace
    trace = go.Scatter(
        x=timestamps,
        y=dest_ports,
        mode='lines',
        marker=dict(color='skyblue'),
        name='Destination Port'
    )

    # Update packet index for next iteration
    packet_index = end_index

    # If packet index reaches the end, reset it to repeat
    if packet_index >= len(packets):
        packet_index = 0

    # Count the number of packets for each protocol
    tcp_count = sum(1 for packet in packets if packet.haslayer(TCP))
    udp_count = sum(1 for packet in packets if packet.haslayer(UDP))
    ssh_count = sum(1 for packet in packets if packet.haslayer(TCP) and packet[TCP].dport == 22)
    ftp_count = sum(1 for packet in packets if packet.haslayer(TCP) and packet[TCP].dport == 21)

    # Create pie chart data
    pie_chart = dcc.Graph(
        id='pie-chart',
        figure={
            'data': [
                go.Pie(
                    labels=['TCP', 'UDP', 'SSH', 'FTP'],
                    values=[tcp_count, udp_count, ssh_count, ftp_count],
                    hole=0.5
                )
            ],
            'layout': go.Layout(
                title='Packet Protocol Distribution'
            )
        }
    )

    return {'data': [trace], 'layout': initial_layout}, pie_chart

if __name__ == '__main__':
    app.run_server(debug=True)
