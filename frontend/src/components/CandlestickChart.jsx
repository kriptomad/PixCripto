import { useEffect, useRef } from 'react';
import { createChart, ColorType, CandlestickSeries } from 'lightweight-charts';

/**
 * Grafico de candles estilo TradingView/Binance, alimentado por
 * `/api/v1/klines` (formato Binance: [open_time, open, high, low, close, volume, close_time]).
 */
export default function CandlestickChart({ candles }) {
  const containerRef = useRef(null);
  const chartRef = useRef(null);
  const seriesRef = useRef(null);

  useEffect(() => {
    if (!containerRef.current) return undefined;

    const chart = createChart(containerRef.current, {
      layout: {
        background: { type: ColorType.Solid, color: 'transparent' },
        textColor: '#8b91a1',
        fontSize: 12,
      },
      grid: {
        vertLines: { color: '#1c212c' },
        horzLines: { color: '#1c212c' },
      },
      width: containerRef.current.clientWidth,
      height: 380,
      timeScale: { timeVisible: true, secondsVisible: false, borderColor: '#232937' },
      rightPriceScale: { borderColor: '#232937' },
      crosshair: { mode: 0 },
    });

    const series = chart.addSeries(CandlestickSeries, {
      upColor: '#16c784',
      downColor: '#ea3943',
      borderVisible: false,
      wickUpColor: '#16c784',
      wickDownColor: '#ea3943',
    });

    chartRef.current = chart;
    seriesRef.current = series;

    const handleResize = () => {
      if (containerRef.current) {
        chart.applyOptions({ width: containerRef.current.clientWidth });
      }
    };
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      chart.remove();
    };
  }, []);

  useEffect(() => {
    if (!seriesRef.current || !candles?.length) return;
    const data = candles.map(([openTime, open, high, low, close]) => ({
      time: Math.floor(openTime / 1000),
      open,
      high,
      low,
      close,
    }));
    seriesRef.current.setData(data);
    chartRef.current?.timeScale().fitContent();
  }, [candles]);

  return <div ref={containerRef} className="w-full" />;
}
