/*
 * Copyright 2021-2026 Open Text.
 *
 * The only warranties for products and services of Open Text
 * and its affiliates and licensors ("Open Text") are as may
 * be set forth in the express warranty statements accompanying
 * such products and services. Nothing herein should be construed
 * as constituting an additional warranty. Open Text shall not be
 * liable for technical or editorial errors or omissions contained
 * herein. The information contained herein is subject to change
 * without notice.
 */
package com.fortify.cli.fpr.compare;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import com.fasterxml.jackson.databind.JsonNode;

public class FprCompareHtmlReportHelper {

    private static final String TEMPLATE_RESOURCE = "com/fortify/cli/fpr/compare/fpr-compare-report.html";
    private static final String DATA_PLACEHOLDER = "/*DATA_PLACEHOLDER*/";

    public static void generateReport(JsonNode compareResult, Path outputFile) {
        try (InputStream is = FprCompareHtmlReportHelper.class.getClassLoader().getResourceAsStream(TEMPLATE_RESOURCE)) {
            if (is == null) {
                throw new IllegalStateException("HTML report template not found on classpath: " + TEMPLATE_RESOURCE);
            }
            String template = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            String json = compareResult.toString().replace("</", "<\\/");
            String html = template.replace(DATA_PLACEHOLDER, json);
            Path parent = outputFile.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.writeString(outputFile, html, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RuntimeException("Failed to generate HTML report: " + outputFile, e);
        }
    }
}
