import type { ReactNode } from "react";

export interface DataColumn<Row> {
  id: string;
  label: string;
  className?: string;
  sortable?: boolean;
  render: (row: Row) => ReactNode;
}

export function DataTable<Row>({
  caption,
  columns,
  rows,
  getRowKey,
  sort,
}: {
  caption: string;
  columns: DataColumn<Row>[];
  rows: Row[];
  getRowKey: (row: Row, index: number) => string;
  sort?: { columnId: string; direction: "asc" | "desc"; onChange: (columnId: string) => void };
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left text-sm">
        <caption className="sr-only">{caption}</caption>
        <thead className="border-y border-rule text-xs text-muted">
          <tr>{columns.map((column) => {
            const active = sort?.columnId === column.id;
            return (
              <th key={column.id} scope="col" aria-sort={active ? (sort.direction === "asc" ? "ascending" : "descending") : undefined} className={`whitespace-nowrap px-3 py-2.5 font-medium ${column.className ?? ""}`}>
                {column.sortable && sort ? <button type="button" onClick={() => sort.onChange(column.id)} className="inline-flex items-center gap-1 text-left hover:text-ink">{column.label}<span aria-hidden="true" className="font-mono">{active ? (sort.direction === "asc" ? "↑" : "↓") : "↕"}</span></button> : column.label}
              </th>
            );
          })}</tr>
        </thead>
        <tbody className="divide-y divide-rule">
          {rows.map((row, index) => (
            <tr key={getRowKey(row, index)}>
              {columns.map((column) => <td key={column.id} className={`px-3 py-3 align-top text-ink ${column.className ?? ""}`}>{column.render(row)}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
