const headers = {
  Authorization: `Bearer ${process.env.METER_API_TOKEN}`,
};

fetch('https://api.example.com/v1/meters', { headers });
