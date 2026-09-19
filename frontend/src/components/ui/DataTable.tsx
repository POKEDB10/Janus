import type { ReactNode } from "react";

export interface DataColumn<Row> {
  id: string;
  label: string;
  className?: string;
  render: (row: Row) => ReactNode;
}

export function DataTable<Row>({
  caption,
  columns,
  rows,
  getRowKey,
  onRowClick,
}: {
  caption: string;
  columns: DataColumn<Row>[];
  rows: Row[];
  getRowKey: (row: Row, index: number) => string;
  onRowClick?: (row: Row) => void;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left text-sm">
        <caption className="sr-only">{caption}</caption>
        <thead className="border-y border-rule text-xs text-muted">
          <tr>{columns.map((column) => <th key={column.id} scope="col" className={`whitespace-nowrap px-3 py-2.5 font-medium ${column.className ?? ""}`}>{column.label}</th>)}</tr>
        </thead>
        <tbody className="divide-y divide-rule">
          {rows.map((row, index) => (
            <tr key={getRowKey(row, index)} className={onRowClick ? "cursor-pointer hover:bg-sunken focus-within:bg-sunken" : ""} onClick={() => onRowClick?.(row)}>
              {columns.map((column) => <td key={column.id} className={`px-3 py-3 align-top text-ink ${column.className ?? ""}`}>{column.render(row)}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
