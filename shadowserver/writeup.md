# Converting Shadowserver data to STIX

[source data](https://www.shadowserver.org/wiki/pmwiki.php/Services/Botnet-CCIP)

We convert each line of input CSV data containing a "known bot server" to a STIX Indicator.

Due to the information source presenting data in the context of detection and mitigation rahter than reporting an existing breach, we use an `Indicator` rather than `Incident` in this case.

Each `Indicator` directly includes the IP address and port number for a single server, with "related" Observables that capture background information about the IP.

Since input data does not include a timestamp, we use the current local time as the timestamp for when the data was created

By including supporting Observables as `related` under the Indicator rather than embedded into the Indicator itself, we decouple the data from its context. This creates an actionable Indicator that can reference an observable as needed.

We set the indicator type to "IP Watchlist", using a `title` that allows for easy identification (in this case the channel name)

The legacy  `channel` tag is not relevant for this data feed, due to the overwhelming use of HTTP bots rather than IRC.

Addresses are stored as a list of the `SocketAddress` type (to capture the IP/port pair). Given that input data may contain multiple IP addresses, we must save them as a list in STIX.

Setting `apply_condition` to `ANY` indicates that each IP address should be matched individually for detection purposes. 

We generate a new GUID to ensure uniqueness of a given `Observable` and `Indicator` for future reference or modification.

An object is created as an  `AddressObject` in cybox with a `category` of `ASN` - to work around a limitation in the Python API.

We use `set_producer_identity` in Python to identify the originator of the information

*Note:* If creating XML via other means, the same can be set using the `<Producer>` field in the Indicator.
